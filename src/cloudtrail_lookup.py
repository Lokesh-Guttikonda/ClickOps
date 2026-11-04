"""Attribute drift to a human: find the CloudTrail event that made the ClickOps change.

Two backends share one parser, so the offline demo exercises the same code path as
production:

* :class:`MockCloudTrailBackend` reads a saved ``aws cloudtrail lookup-events`` response.
* :class:`AwsCliCloudTrailBackend` shells out to the AWS CLI (pre-installed on GitHub
  runners), which keeps boto3 out of the dependency tree. It needs
  ``cloudtrail:LookupEvents`` only.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import shutil
import subprocess
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

from .detector import DriftItem

log = logging.getLogger(__name__)


class CloudTrailError(RuntimeError):
    """CloudTrail could not be queried."""


#: CloudTrail event names that can change each resource type. Used to rank candidate
#: events and as a fallback search when ``ResourceName`` lookups return nothing.
EXPECTED_EVENTS: dict[str, tuple[str, ...]] = {
    "aws_security_group": (
        "ModifySecurityGroupRules",
        "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupEgress",
        "UpdateSecurityGroupRuleDescriptionsIngress",
        "UpdateSecurityGroupRuleDescriptionsEgress",
        "CreateTags",
        "DeleteTags",
    ),
    "aws_security_group_rule": (
        "ModifySecurityGroupRules",
        "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupEgress",
    ),
    "aws_vpc_security_group_ingress_rule": (
        "ModifySecurityGroupRules",
        "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress",
        "CreateTags",
        "DeleteTags",
    ),
    "aws_vpc_security_group_egress_rule": (
        "ModifySecurityGroupRules",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupEgress",
        "CreateTags",
        "DeleteTags",
    ),
    "aws_instance": (
        "ModifyInstanceAttribute",
        "ModifyInstanceMetadataOptions",
        "ModifyInstanceCreditSpecification",
        "AssociateIamInstanceProfile",
        "ReplaceIamInstanceProfileAssociation",
        "StopInstances",
        "StartInstances",
        "CreateTags",
        "DeleteTags",
    ),
    "aws_s3_bucket": (
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketAcl",
        "PutBucketTagging",
        "DeleteBucketTagging",
        "PutBucketVersioning",
        "PutBucketEncryption",
        "PutBucketPublicAccessBlock",
        "PutBucketLogging",
        "PutBucketCors",
        "PutBucketLifecycle",
    ),
    "aws_db_instance": ("ModifyDBInstance", "AddTagsToResource", "RemoveTagsFromResource"),
    "aws_iam_role": (
        "UpdateRole",
        "UpdateAssumeRolePolicy",
        "AttachRolePolicy",
        "DetachRolePolicy",
        "PutRolePolicy",
        "DeleteRolePolicy",
        "TagRole",
        "UntagRole",
    ),
    "aws_iam_policy": ("CreatePolicyVersion", "SetDefaultPolicyVersion", "TagPolicy", "UntagPolicy"),
    "aws_lambda_function": (
        "UpdateFunctionConfiguration20150331v2",
        "UpdateFunctionCode20150331v2",
        "TagResource",
        "UntagResource",
    ),
    "aws_autoscaling_group": ("UpdateAutoScalingGroup", "CreateOrUpdateTags", "DeleteTags"),
}

_TERRAFORM_AGENTS = ("terraform/", "hashicorp", "terraform-provider-aws")


def parse_time(value: Any) -> datetime:
    """Parse CloudTrail/AWS CLI timestamps (ISO-8601 with ``Z`` or offset, or epoch)."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- events


@dataclass(frozen=True)
class ChangeEvent:
    """A CloudTrail management event, reduced to what an auditor needs."""

    event_id: str
    event_name: str
    event_time: datetime
    event_source: str
    actor: str
    identity_type: str
    principal_arn: str | None
    role_name: str | None
    access_key_id: str | None
    source_ip: str | None
    user_agent: str | None
    via_console: bool
    mfa_authenticated: bool | None
    region: str | None
    read_only: bool
    resources: tuple[str, ...]
    raw_detail: str = field(default="", repr=False, compare=False)

    @property
    def channel(self) -> str:
        agent = (self.user_agent or "").lower()
        if self.via_console:
            return "AWS Console"
        if any(marker in agent for marker in _TERRAFORM_AGENTS):
            return "Terraform"
        if agent.startswith("aws-cli"):
            return "AWS CLI"
        if "cloudformation" in agent:
            return "CloudFormation"
        if "boto" in agent or "aws-sdk" in agent:
            return "AWS SDK"
        return "API" if agent else "unknown"

    @property
    def is_terraform(self) -> bool:
        return self.channel == "Terraform"

    def references(self, identifier: str | None) -> bool:
        return bool(identifier) and (identifier in self.resources or identifier in self.raw_detail)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_name": self.event_name,
            "event_time": _iso(self.event_time),
            "event_source": self.event_source,
            "actor": self.actor,
            "identity_type": self.identity_type,
            "principal_arn": self.principal_arn,
            "role_name": self.role_name,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "channel": self.channel,
            "mfa_authenticated": self.mfa_authenticated,
            "region": self.region,
        }


def _identity(ui: dict[str, Any], fallback: str | None) -> tuple[str, str | None]:
    """Return a human-friendly actor name and (for assumed roles) the role name."""
    kind = ui.get("type", "")
    arn = ui.get("arn") or ""
    if kind == "IAMUser":
        return ui.get("userName") or arn.rsplit("/", 1)[-1] or fallback or "unknown", None
    if kind == "AssumedRole":
        issuer = (ui.get("sessionContext") or {}).get("sessionIssuer") or {}
        role = issuer.get("userName") or (arn.split("/")[1] if arn.count("/") >= 2 else None)
        session = arn.rsplit("/", 1)[-1] if "/" in arn else fallback
        return session or role or "unknown", role
    if kind == "Root":
        return "root", None
    if kind == "FederatedUser":
        return arn.rsplit("/", 1)[-1] or fallback or "unknown", None
    if kind == "AWSService":
        return ui.get("invokedBy") or "aws-service", None
    if kind in ("IdentityCenterUser", "Unknown"):
        return ui.get("userName") or ui.get("principalId") or fallback or "unknown", None
    return fallback or ui.get("principalId") or "unknown", None


def parse_lookup_event(raw: dict[str, Any]) -> ChangeEvent:
    """Parse one element of ``LookupEvents``' ``Events`` list."""
    detail_raw = raw.get("CloudTrailEvent") or "{}"
    try:
        detail = json.loads(detail_raw) if isinstance(detail_raw, str) else dict(detail_raw)
    except json.JSONDecodeError:
        detail = {}
    if not isinstance(detail_raw, str):
        detail_raw = json.dumps(detail_raw)
    ui = detail.get("userIdentity") or {}
    actor, role = _identity(ui, raw.get("Username"))
    agent = detail.get("userAgent")
    attributes = ((ui.get("sessionContext") or {}).get("attributes")) or {}
    mfa = attributes.get("mfaAuthenticated")
    read_only = raw.get("ReadOnly", detail.get("readOnly", False))
    console = str(detail.get("sessionCredentialFromConsole", "")).lower() == "true" or (
        isinstance(agent, str) and agent.startswith(("console.", "signin.amazonaws.com"))
    )
    resources = tuple(r.get("ResourceName", "") for r in raw.get("Resources") or [] if r.get("ResourceName"))
    return ChangeEvent(
        event_id=raw.get("EventId") or detail.get("eventID") or "",
        event_name=raw.get("EventName") or detail.get("eventName") or "",
        event_time=parse_time(raw.get("EventTime") or detail.get("eventTime")),
        event_source=raw.get("EventSource") or detail.get("eventSource") or "",
        actor=actor,
        identity_type=ui.get("type") or "unknown",
        principal_arn=ui.get("arn"),
        role_name=role,
        access_key_id=raw.get("AccessKeyId") or ui.get("accessKeyId"),
        source_ip=detail.get("sourceIPAddress"),
        user_agent=agent,
        via_console=console,
        mfa_authenticated=None if mfa is None else str(mfa).lower() == "true",
        region=detail.get("awsRegion"),
        read_only=str(read_only).lower() == "true",
        resources=resources,
        raw_detail=detail_raw,
    )


# --------------------------------------------------------------------------- backends


class CloudTrailBackend(Protocol):
    name: str

    def lookup(self, attribute_key: str, attribute_value: str, start: datetime, end: datetime) -> list[dict]:
        """Return raw ``LookupEvents`` events matching one lookup attribute."""


class MockCloudTrailBackend:
    """Serve events from a saved ``aws cloudtrail lookup-events --output json`` response."""

    name = "mock"

    def __init__(self, source: str | os.PathLike[str] | dict | list) -> None:
        if isinstance(source, (str, os.PathLike)):
            try:
                shown = os.path.relpath(source)
            except ValueError:  # different drive on Windows
                shown = str(source)
            self.label = f"mock: {Path(shown).as_posix() if not shown.startswith('..') else Path(source).name}"
            data = json.loads(Path(source).read_text(encoding="utf-8"))
        else:
            self.label = "in-memory"
            data = source
        self.events: list[dict] = data.get("Events", []) if isinstance(data, dict) else list(data)

    def lookup(self, attribute_key: str, attribute_value: str, start: datetime, end: datetime) -> list[dict]:
        matches = []
        for event in self.events:
            detail = json.loads(event.get("CloudTrailEvent") or "{}")
            when = parse_time(event.get("EventTime") or detail.get("eventTime"))
            if not (start <= when <= end):
                continue
            if attribute_key == "ResourceName":
                values = {r.get("ResourceName") for r in event.get("Resources") or []}
            else:  # EventName, Username, EventSource, ... are top-level fields
                values = {event.get(attribute_key)}
            if attribute_value in values:
                matches.append(event)
        return matches


class AwsCliCloudTrailBackend:
    """Query CloudTrail event history with ``aws cloudtrail lookup-events``."""

    name = "aws"

    def __init__(
        self,
        *,
        region: str | None = None,
        profile: str | None = None,
        max_items: int = 200,
        aws_bin: str = "aws",
        timeout: float = 120,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    ) -> None:
        self.region = region
        self.profile = profile
        self.max_items = max_items
        self.aws_bin = aws_bin
        self.timeout = timeout
        self.runner = runner
        self.label = f"aws cloudtrail lookup-events ({region or 'default region'})"

    @staticmethod
    def available(aws_bin: str = "aws") -> bool:
        return shutil.which(aws_bin) is not None

    def lookup(self, attribute_key: str, attribute_value: str, start: datetime, end: datetime) -> list[dict]:
        cmd = [
            self.aws_bin,
            "cloudtrail",
            "lookup-events",
            "--lookup-attributes",
            json.dumps([{"AttributeKey": attribute_key, "AttributeValue": attribute_value}]),
            "--start-time",
            _iso(start),
            "--end-time",
            _iso(end),
            "--max-items",
            str(self.max_items),
            "--output",
            "json",
        ]
        if self.region:
            cmd += ["--region", self.region]
        if self.profile:
            cmd += ["--profile", self.profile]
        try:
            proc = self.runner(cmd, capture_output=True, text=True, timeout=self.timeout)
        except FileNotFoundError as exc:
            raise CloudTrailError(f"`{self.aws_bin}` not found; install the AWS CLI") from exc
        except subprocess.TimeoutExpired as exc:
            raise CloudTrailError("aws cloudtrail lookup-events timed out") from exc
        if proc.returncode != 0:
            raise CloudTrailError(f"aws cloudtrail lookup-events failed: {(proc.stderr or '').strip()[:500]}")
        try:
            return json.loads(proc.stdout or "{}").get("Events", [])
        except json.JSONDecodeError as exc:
            raise CloudTrailError("could not parse aws cloudtrail lookup-events output") from exc


# --------------------------------------------------------------------------- attribution


@dataclass
class Attribution:
    address: str
    resource_id: str | None
    events: list[ChangeEvent]
    primary: ChangeEvent | None
    confidence: str  # high | medium | low | none
    note: str = ""
    discarded: int = 0  # read-only, Terraform-made or ignored-principal events filtered out

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "resource_id": self.resource_id,
            "confidence": self.confidence,
            "note": self.note,
            "discarded": self.discarded,
            "primary": self.primary.to_dict() if self.primary else None,
            "events": [e.to_dict() for e in self.events],
        }


class CloudTrailLookup:
    """Find who changed a drifted resource.

    Events that are read-only, made by Terraform itself, or made by an ignored principal
    (e.g. your CI deploy role) are discarded. The most recent remaining event of a type
    that can change the resource is the primary suspect.
    """

    def __init__(
        self,
        backend: CloudTrailBackend,
        *,
        lookback: timedelta = timedelta(days=7),
        ignore_principals: Iterable[str] = (),
        include_terraform: bool = False,
        max_event_name_queries: int = 6,
    ) -> None:
        self.backend = backend
        self.lookback = lookback
        self.ignore_principals = tuple(p for p in ignore_principals if p)
        self.include_terraform = include_terraform
        self.max_event_name_queries = max_event_name_queries

    def _ignored(self, event: ChangeEvent) -> bool:
        if event.read_only:
            return True
        if event.is_terraform and not self.include_terraform:
            return True
        names = [n for n in (event.actor, event.principal_arn, event.role_name) if n]
        return any(fnmatch.fnmatchcase(n, pattern) for n in names for pattern in self.ignore_principals)

    def attribute(self, item: DriftItem, *, end: datetime | None = None) -> Attribution:
        end = end or datetime.now(timezone.utc)
        start = end - self.lookback
        identifiers = [i for i in (item.resource_id, item.arn) if i]
        if not identifiers:
            return Attribution(item.address, None, [], None, "none", "resource has no id to search for")

        raw: dict[str, dict] = {}
        for identifier in identifiers:
            for event in self.backend.lookup("ResourceName", identifier, start, end):
                raw.setdefault(event.get("EventId") or json.dumps(event, sort_keys=True), event)
        expected = EXPECTED_EVENTS.get(item.type, ())
        if not raw:
            # Not every API call lists the resource in "Resources"; search by event name
            # and keep events whose payload mentions the resource id.
            for event_name in expected[: self.max_event_name_queries]:
                for event in self.backend.lookup("EventName", event_name, start, end):
                    payload = json.dumps(event)
                    if any(identifier in payload for identifier in identifiers):
                        raw.setdefault(event.get("EventId") or payload, event)

        parsed = [parse_lookup_event(e) for e in raw.values()]
        events = sorted((e for e in parsed if not self._ignored(e)), key=lambda e: e.event_time, reverse=True)
        discarded = len(parsed) - len(events)
        hours = int(self.lookback.total_seconds() // 3600)
        if not events:
            return Attribution(
                item.address,
                item.resource_id,
                [],
                None,
                "none",
                f"no ClickOps events for this resource in the last {hours}h "
                f"({discarded} Terraform/read-only/ignored event(s) skipped)",
                discarded,
            )
        relevant = [e for e in events if e.event_name in expected]
        primary = relevant[0] if relevant else events[0]
        refs = any(primary.references(i) for i in identifiers)
        known = primary.event_name in expected
        confidence = "high" if refs and known else "medium" if refs or known else "low"
        return Attribution(item.address, item.resource_id, events, primary, confidence, discarded=discarded)


def build_backend(
    mode: str,
    *,
    events_file: str | os.PathLike[str] | None = None,
    region: str | None = None,
    profile: str | None = None,
) -> CloudTrailBackend | None:
    """``mode`` is ``auto`` | ``aws`` | ``mock`` | ``off``."""
    mode = (mode or "auto").lower()
    if mode == "off":
        return None
    if mode == "mock" or (mode == "auto" and events_file):
        if not events_file:
            raise CloudTrailError("--cloudtrail mock needs --cloudtrail-events FILE")
        return MockCloudTrailBackend(events_file)
    if mode == "aws" or (mode == "auto" and AwsCliCloudTrailBackend.available()):
        return AwsCliCloudTrailBackend(region=region, profile=profile)
    if mode == "auto":
        log.warning("AWS CLI not found; skipping CloudTrail attribution")
        return None
    raise CloudTrailError(f"unknown CloudTrail mode {mode!r} (use auto, aws, mock or off)")


def parse_principal_patterns(values: Sequence[str] | str | None) -> list[str]:
    """Accept repeated flags and/or comma/newline separated lists."""
    if not values:
        return []
    if isinstance(values, str):
        values = [values]
    out: list[str] = []
    for value in values:
        out += [p.strip() for p in value.replace("\n", ",").split(",") if p.strip()]
    return out
