"""``terradrift`` command line interface.

Exit codes: 0 = success (drift or not), 1 = error, 3 = drift found with ``--fail-on-drift``.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .cloudtrail_lookup import CloudTrailError, parse_principal_patterns
from .detector import TerraformError, detect_drift, load_plan, run_terraform_plan
from .hcl import HclError
from .hcl_patcher import APPLIED, IN_SYNC, SUPPORTED_PROVIDERS, ConfigError
from .pr_creator import PRError, PullRequestResult, display_path, open_or_update_pull_request, render_pr_body
from .reconciler import ReconcileConfig, ReconcileReport, reconcile

EXIT_OK, EXIT_ERROR, EXIT_DRIFT = 0, 1, 3


class Style:
    """Tiny ANSI helper that honours NO_COLOR and non-TTY output."""

    def __init__(self, enabled: bool | None = None) -> None:
        if enabled is None:
            enabled = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)

    def diff(self, text: str) -> str:
        lines = []
        for line in text.splitlines():
            if line.startswith(("+++", "---")):
                lines.append(self.bold(line))
            elif line.startswith("+"):
                lines.append(self.green(line))
            elif line.startswith("-"):
                lines.append(self.red(line))
            elif line.startswith("@@"):
                lines.append(self.cyan(line))
            else:
                lines.append(line)
        return "\n".join(lines)


def format_value(value: Any, sensitive: bool = False, limit: int = 60) -> str:
    if sensitive:
        return "(sensitive)"
    text = json.dumps(value, sort_keys=True, default=str)
    return text if len(text) <= limit else text[: limit - 3] + "..."


_KIND_SYMBOL = {"modified": "~", "added": "+", "removed": "-"}
_RISK_COLOR = {"critical": "red", "high": "red", "medium": "yellow", "low": "green", "info": "cyan", "none": "green"}


def render_text_summary(report: ReconcileReport, *, base_dir: Path | None = None, style: Style | None = None) -> str:
    s = style or Style(False)
    items = report.drift.actionable_items
    if not items:
        extra = ""
        if report.drift.items:
            extra = f" ({len(report.drift.items)} resource(s) have state-only drift that needs no code change)"
        return s.green("terradrift-ai: no ClickOps drift; infrastructure matches the code") + extra
    risk = report.risk
    colour = getattr(s, _RISK_COLOR.get(risk, "bold"))
    lines = [
        s.bold(f"terradrift-ai: {len(items)} resource(s) changed outside Terraform")
        + f" (risk: {colour(risk.upper())})"
    ]
    outcomes = {(o.address, o.change.path if o.change else None): o for o in report.patch.outcomes}
    for item in items:
        lines.append(f"  {s.bold(item.address)}" + (s.red("  [DELETED outside Terraform]") if item.deleted else ""))
        for change in item.actionable_changes:
            outcome = outcomes.get((item.address, change.path))
            status = "?"
            if outcome is not None:
                if outcome.status == APPLIED:
                    status = s.green("codified" + (f" by {outcome.engine}" if outcome.engine != "rules" else ""))
                elif outcome.status == IN_SYNC:
                    status = s.dim("already in code")
                else:
                    status = s.yellow(f"manual: {outcome.reason}")
            lines.append(
                f"    {_KIND_SYMBOL.get(change.kind, '~')} {change.dotted}: "
                f"{format_value(change.before, change.sensitive)} -> {format_value(change.after, change.sensitive)}"
                f"  [{status}]"
            )
        attribution = report.attributions.get(item.address)
        if attribution is not None:
            event = attribution.primary
            if event is None:
                lines.append(s.dim(f"    changed by: unknown ({attribution.note})"))
            else:
                where = ", ".join(x for x in (event.identity_type, event.channel, event.source_ip) if x)
                lines.append(
                    f"    changed by {s.bold(event.actor)} ({where}) via {event.event_name} at "
                    f"{event.event_time:%Y-%m-%d %H:%M:%S} UTC [confidence: {attribution.confidence}]"
                )
    for finding in report.risks:
        lines.append(
            f"  risk {getattr(s, _RISK_COLOR.get(finding.level, 'bold'))(finding.level.upper())}: {finding.message}"
        )
    for fp in report.patch.files:
        added, removed = fp.stats()
        lines.append(f"  patched {display_path(fp.path, base_dir)} (+{added} -{removed})")
    for warning in report.warnings + report.patch.warnings:
        lines.append(s.yellow(f"  warning: {warning}"))
    return "\n".join(lines)


def _repo_root(start: Path) -> Path | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], cwd=start, capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return Path(proc.stdout.strip()) if proc.returncode == 0 and proc.stdout.strip() else None


def _write_github_outputs(report: ReconcileReport, pr: PullRequestResult | None, summary_file: str | None) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    values = {
        "drift-detected": str(report.has_drift).lower(),
        "risk": report.risk,
        "fingerprint": report.fingerprint if report.has_drift else "",
        "changed-files": ",".join(str(f.path) for f in report.patch.files),
        "pr-action": pr.action if pr else "",
        "pr-url": (pr.url or "") if pr else "",
        "summary-file": summary_file or "",
    }
    with open(path, "a", encoding="utf-8") as fh:
        for key, value in values.items():
            fh.write(f"{key}={value.replace(chr(10), ' ')}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="terradrift",
        description="Detect Terraform ClickOps drift, find who made it in CloudTrail, patch the HCL, open a PR.",
    )
    parser.add_argument("--version", action="version", version=f"terradrift-ai {__version__}")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="more logging (-vv for debug)")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-C", "--workdir", default=".", help="Terraform root module directory (default: .)")
    common.add_argument(
        "--plan-json", help="read an existing `terraform show -json` file instead of running terraform plan"
    )
    common.add_argument("--refresh-only", action="store_true", help="run/interpret the plan as -refresh-only")
    common.add_argument("--terraform-bin", default=os.environ.get("TERRAFORM_BIN", "terraform"))
    common.add_argument("--var-file", action="append", default=[], help="passed to terraform plan (repeatable)")
    common.add_argument("--fail-on-drift", action="store_true", help=f"exit {EXIT_DRIFT} when drift is found")

    detect = sub.add_parser("detect", parents=[common], help="report drift without changing anything")
    detect.add_argument("--json", action="store_true", help="print machine-readable JSON")

    rec = sub.add_parser("reconcile", parents=[common], help="detect, attribute, patch and optionally open a PR")
    rec.add_argument("--provider", choices=SUPPORTED_PROVIDERS, help="patch engine (default: $PROVIDER, else mock)")
    rec.add_argument("--cloudtrail", choices=("auto", "aws", "mock", "off"), default="auto")
    rec.add_argument("--cloudtrail-events", help="saved `aws cloudtrail lookup-events` JSON (offline attribution)")
    rec.add_argument("--aws-region", default=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"))
    rec.add_argument("--aws-profile", default=os.environ.get("AWS_PROFILE"))
    rec.add_argument("--lookback-hours", type=int, default=int(os.environ.get("TERRADRIFT_LOOKBACK_HOURS", 168)))
    rec.add_argument(
        "--ignore-principal",
        action="append",
        default=[],
        help="glob of IAM principals whose events are not ClickOps, e.g. your CI role (repeatable/comma separated; "
        "also $TERRADRIFT_IGNORE_PRINCIPALS)",
    )
    where = rec.add_mutually_exclusive_group()
    where.add_argument("--dry-run", action="store_true", help="write nothing; print the diff")
    where.add_argument("--output-dir", help="write patched files under this directory instead of in place")
    rec.add_argument("--summary-file", help="write the Markdown PR description to this file")
    rec.add_argument("--json-file", help="write the machine-readable report to this file")
    rec.add_argument("--create-pr", action="store_true", help="commit to a branch and open/refresh a GitHub PR")
    rec.add_argument("--base", help="PR base branch (default: the repository's default branch)")
    rec.add_argument("--label", action="append", default=[], help="PR label (repeatable)")
    rec.add_argument("--draft", action="store_true", help="open the PR as a draft")
    rec.add_argument("--no-color", action="store_true")
    return parser


def _detect(args: argparse.Namespace) -> int:
    if args.plan_json:
        plan, source = load_plan(args.plan_json), args.plan_json
    else:
        plan = run_terraform_plan(
            args.workdir, terraform_bin=args.terraform_bin, refresh_only=args.refresh_only, var_files=args.var_file
        )
        source = f"terraform plan ({args.workdir})"
    drift = detect_drift(plan, refresh_only=args.refresh_only, source=source)
    if args.json:
        print(json.dumps(drift.to_dict(), indent=2, default=str))
    elif not drift.has_drift:
        print("no ClickOps drift: infrastructure matches the code")
    else:
        for item in drift.actionable_items:
            print(item.address + ("  [DELETED]" if item.deleted else ""))
            for change in item.actionable_changes:
                print(
                    f"  {_KIND_SYMBOL.get(change.kind, '~')} {change.dotted}: "
                    f"{format_value(change.before, change.sensitive)} -> {format_value(change.after, change.sensitive)}"
                )
    return EXIT_DRIFT if args.fail_on_drift and drift.has_drift else EXIT_OK


def _reconcile(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.create_pr and (args.dry_run or args.output_dir):
        parser.error("--create-pr commits files in place; it cannot be combined with --dry-run or --output-dir")
    cloudtrail = args.cloudtrail
    if args.cloudtrail_events and cloudtrail == "auto":
        cloudtrail = "mock"
    config = ReconcileConfig(
        workdir=Path(args.workdir),
        plan_json=Path(args.plan_json) if args.plan_json else None,
        refresh_only=args.refresh_only,
        terraform_bin=args.terraform_bin,
        var_files=args.var_file,
        provider=args.provider,
        cloudtrail=cloudtrail,
        cloudtrail_events=Path(args.cloudtrail_events) if args.cloudtrail_events else None,
        aws_region=args.aws_region,
        aws_profile=args.aws_profile,
        lookback_hours=args.lookback_hours,
        ignore_principals=parse_principal_patterns(
            args.ignore_principal + [os.environ.get("TERRADRIFT_IGNORE_PRINCIPALS", "")]
        ),
    )
    report = reconcile(config)
    style = Style(False if args.no_color else None)
    base_dir = _repo_root(Path(args.workdir).resolve()) or Path.cwd()

    if report.patch.files and not args.dry_run:
        report.patch.write(args.output_dir, root=config.workdir)

    body = render_pr_body(report, base_dir=base_dir)
    if args.summary_file:
        Path(args.summary_file).write_text(body, encoding="utf-8")
    if args.json_file:
        Path(args.json_file).write_text(json.dumps(report.to_dict(), indent=2, default=str) + "\n", encoding="utf-8")
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary and report.has_drift:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(body + "\n")

    print(render_text_summary(report, base_dir=base_dir, style=style))
    if args.dry_run:
        for fp in report.patch.files:
            print()
            print(style.diff(fp.diff(display_path(fp.path, base_dir))))

    pr: PullRequestResult | None = None
    if args.create_pr and report.has_drift:
        pr = open_or_update_pull_request(
            report, repo_root=base_dir, base=args.base, labels=args.label, draft=args.draft
        )
        print(f"pull request {pr.action}: {pr.url or '-'}" + (f" ({pr.message})" if pr.message else ""))
    _write_github_outputs(report, pr, args.summary_file)
    return EXIT_DRIFT if args.fail_on_drift and report.has_drift else EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    level = logging.WARNING - 10 * min(args.verbose, 2)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")  # emoji-safe on legacy Windows consoles
    try:
        if args.command == "detect":
            return _detect(args)
        return _reconcile(args, parser)
    except BrokenPipeError:  # e.g. `terradrift ... | head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return EXIT_OK
    except (TerraformError, CloudTrailError, ConfigError, PRError, HclError, OSError) as exc:
        print(f"terradrift: error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
