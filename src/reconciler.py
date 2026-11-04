"""Orchestrates the pipeline: detect -> attribute -> patch -> assess risk."""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .cloudtrail_lookup import (
    Attribution,
    CloudTrailBackend,
    CloudTrailError,
    CloudTrailLookup,
    build_backend,
    parse_time,
)
from .detector import DriftReport, detect_drift, load_plan, run_terraform_plan
from .hcl_patcher import HclPatcher, PatchResult, get_patcher
from .risk import RiskFinding, assess_risk, overall_level

log = logging.getLogger(__name__)


@dataclass
class ReconcileConfig:
    workdir: Path = Path(".")
    plan_json: Path | None = None
    refresh_only: bool = False
    terraform_bin: str = "terraform"
    var_files: Sequence[str] = ()
    provider: str | None = None  # falls back to $PROVIDER, then "mock"
    cloudtrail: str = "auto"  # auto | aws | mock | off
    cloudtrail_events: Path | None = None
    aws_region: str | None = None
    aws_profile: str | None = None
    lookback_hours: int = 168
    ignore_principals: Sequence[str] = ()


@dataclass
class ReconcileReport:
    config: ReconcileConfig
    drift: DriftReport
    attributions: dict[str, Attribution]
    patch: PatchResult
    risks: list[RiskFinding]
    cloudtrail_source: str | None
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    warnings: list[str] = field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return self.drift.has_drift

    @property
    def risk(self) -> str:
        return overall_level(self.risks)

    @property
    def fingerprint(self) -> str:
        """Stable id of *this* drift, used to dedupe PRs across scheduled runs."""
        parts = []
        for item in self.drift.actionable_items:
            if item.deleted:
                parts.append([item.address, "<deleted>"])
            for change in item.actionable_changes:
                value = "<sensitive>" if change.sensitive else change.after
                parts.append([item.address, change.dotted, value])
        digest = hashlib.sha256(json.dumps(sorted(parts, key=str), sort_keys=True, default=str).encode())
        return digest.hexdigest()[:16]

    @property
    def actors(self) -> list[str]:
        seen: list[str] = []
        for attribution in self.attributions.values():
            if attribution.primary and attribution.primary.actor not in seen:
                seen.append(attribution.primary.actor)
        return seen

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": __version__,
            "generated_at": self.generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "fingerprint": self.fingerprint,
            "has_drift": self.has_drift,
            "risk": self.risk,
            "drift": self.drift.to_dict(),
            "cloudtrail_source": self.cloudtrail_source,
            "attributions": {k: v.to_dict() for k, v in self.attributions.items()},
            "risks": [r.to_dict() for r in self.risks],
            "patch": self.patch.to_dict(),
            "warnings": self.warnings + self.patch.warnings,
        }


def _window_end(drift: DriftReport) -> datetime:
    """CloudTrail search ends when the plan ran (or now, if the plan has no timestamp)."""
    if drift.timestamp:
        try:
            return parse_time(drift.timestamp) + timedelta(minutes=5)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def reconcile(
    config: ReconcileConfig,
    *,
    cloudtrail_backend: CloudTrailBackend | None = None,
    patcher: HclPatcher | None = None,
    terraform_runner: Callable[..., Any] | None = None,
) -> ReconcileReport:
    """Run the whole pipeline. Never writes files; call ``report.patch.write()`` for that."""
    workdir = Path(config.workdir)
    warnings: list[str] = []

    # 1. detect ---------------------------------------------------------------
    if config.plan_json:
        plan = load_plan(config.plan_json)
        source = str(config.plan_json)
    else:
        kwargs: dict[str, Any] = {}
        if terraform_runner is not None:
            kwargs["runner"] = terraform_runner
        plan = run_terraform_plan(
            workdir,
            terraform_bin=config.terraform_bin,
            refresh_only=config.refresh_only,
            var_files=config.var_files,
            **kwargs,
        )
        source = f"terraform plan ({workdir})"
    drift = detect_drift(plan, refresh_only=config.refresh_only, source=source)
    log.info("%d drifted resource(s), %d need action", len(drift.items), len(drift.actionable_items))

    # 2. attribute ------------------------------------------------------------
    attributions: dict[str, Attribution] = {}
    backend = cloudtrail_backend
    if backend is None and drift.has_drift:
        try:
            backend = build_backend(
                config.cloudtrail,
                events_file=config.cloudtrail_events,
                region=config.aws_region,
                profile=config.aws_profile,
            )
        except CloudTrailError as exc:
            warnings.append(f"CloudTrail attribution disabled: {exc}")
    cloudtrail_source = getattr(backend, "label", getattr(backend, "name", None)) if backend else None
    if backend is not None:
        lookup = CloudTrailLookup(
            backend, lookback=timedelta(hours=config.lookback_hours), ignore_principals=config.ignore_principals
        )
        end = _window_end(drift)
        for item in drift.actionable_items:
            try:
                attributions[item.address] = lookup.attribute(item, end=end)
            except CloudTrailError as exc:
                warnings.append(f"CloudTrail lookup failed for {item.address}: {exc}")
                break

    # 3. patch ----------------------------------------------------------------
    patcher = patcher or get_patcher(config.provider)
    patch = patcher.patch(drift, workdir)

    # 4. risk -----------------------------------------------------------------
    risks = assess_risk(drift)

    return ReconcileReport(
        config=config,
        drift=drift,
        attributions=attributions,
        patch=patch,
        risks=risks,
        cloudtrail_source=cloudtrail_source,
        warnings=warnings,
    )
