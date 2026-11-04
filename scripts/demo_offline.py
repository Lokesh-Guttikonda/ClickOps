#!/usr/bin/env python3
"""terradrift-ai offline demo: zero cloud credentials, zero API keys, zero dependencies.

    python scripts/demo_offline.py

Walks the full pipeline over the files in examples/:

  1. detect   -- parse examples/drifted_plan.json (a `terraform show -json` plan)
  2. who      -- find the ClickOps change in examples/cloudtrail_events.json
  3. patch    -- rewrite the security group in examples/main.tf to match AWS
  4. PR       -- render the Markdown pull request (nothing is pushed)

By default the patched file goes to demo_output/main.tf so the repository stays clean;
pass --in-place to patch examples/main.tf itself. Set PROVIDER=groq|gemini|anthropic (plus
the matching API key) to add the LLM step; the default PROVIDER=mock never touches the network.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.cli import Style, format_value  # noqa: E402
from src.pr_creator import display_path, render_pr_body, render_pr_title  # noqa: E402
from src.reconciler import ReconcileConfig, reconcile  # noqa: E402

EXAMPLES = ROOT / "examples"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--output-dir", default=str(ROOT / "demo_output"), help="where to write results")
    parser.add_argument("--in-place", action="store_true", help="patch examples/main.tf itself")
    parser.add_argument("--provider", help="override $PROVIDER (default: mock)")
    parser.add_argument("--quiet", action="store_true", help="don't print the PR markdown")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    s = Style(False if args.no_color else None)
    provider = (args.provider or os.environ.get("PROVIDER") or "mock").lower()
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(s.bold("terradrift-ai offline demo") + s.dim(f"  (PROVIDER={provider}; no AWS credentials needed)"))
    print()

    report = reconcile(
        ReconcileConfig(
            workdir=EXAMPLES,
            plan_json=EXAMPLES / "drifted_plan.json",
            provider=provider,
            cloudtrail="mock",
            cloudtrail_events=EXAMPLES / "cloudtrail_events.json",
        )
    )

    # 1. detect ---------------------------------------------------------------
    items = report.drift.actionable_items
    print(_step(s, 1, "Detect drift") + display_path(EXAMPLES / "drifted_plan.json", ROOT))
    if not items:
        print("      no ClickOps drift found")
        return 0
    for item in items:
        count = len(item.actionable_changes)
        print(f"      {s.red('DRIFT')} {s.bold(item.address)}: {count} attribute(s) changed outside Terraform")
        for change in item.actionable_changes:
            print(f"        {change.dotted}: {format_value(change.before)} -> {s.bold(format_value(change.after))}")

    # 2. attribute ------------------------------------------------------------
    print()
    print(_step(s, 2, "Who did it?") + f"CloudTrail ({report.cloudtrail_source})")
    for item in items:
        attribution = report.attributions.get(item.address)
        event = attribution.primary if attribution else None
        if event is None:
            print(f"      {item.address}: unknown")
            continue
        print(f"      who:        {s.bold(event.actor)} ({event.identity_type} {event.principal_arn})")
        print(f"      what:       {event.event_name} at {event.event_time:%Y-%m-%d %H:%M:%S} UTC")
        print(f"      from:       {event.channel}, {event.source_ip}, MFA={'yes' if event.mfa_authenticated else 'no'}")
        print(f"      confidence: {attribution.confidence}")
        print(
            s.dim(
                f"      skipped {attribution.discarded} other event(s) on this resource "
                "(read-only calls, Terraform's own apply)"
            )
        )

    # 3. patch ----------------------------------------------------------------
    print()
    print(_step(s, 3, "Patch Terraform") + report.patch.engine)
    for fp in report.patch.files:
        print(s.diff(fp.diff(display_path(fp.path, ROOT))))
    if args.in_place:
        written = report.patch.write()
    else:
        written = report.patch.write(out_dir, root=EXAMPLES)
    for path in written:
        print(f"      wrote {display_path(path, ROOT)}")
    if not report.patch.files and not report.patch.skipped:
        print(s.green("      code already matches the live values; nothing to patch"))
    for outcome in report.patch.skipped:
        print(
            s.yellow(
                f"      manual: {outcome.address} {outcome.change.dotted if outcome.change else ''}: {outcome.reason}"
            )
        )
    for warning in report.warnings + report.patch.warnings:
        print(s.yellow(f"      warning: {warning}"))

    # 4. pull request ---------------------------------------------------------
    body = render_pr_body(report, base_dir=ROOT)
    summary = out_dir / "PR_SUMMARY.md"
    summary.write_text(body, encoding="utf-8")
    (out_dir / "report.json").write_text(json.dumps(report.to_dict(), indent=2, default=str) + "\n", encoding="utf-8")
    print()
    print(_step(s, 4, "Pull request") + "dry run: nothing is pushed")
    print(f"      title: {render_pr_title(report)}")
    print(f"      risk:  {report.risk.upper()}")
    print(f"      body:  {display_path(summary, ROOT)}  (+ report.json)")
    if not args.quiet:
        print()
        print(s.dim("-" * 30 + " PR_SUMMARY.md " + "-" * 30))
        print(body)
    return 0


def _step(s: Style, n: int, title: str) -> str:
    return s.cyan(f"[{n}/4] {title}".ljust(24))


if __name__ == "__main__":
    raise SystemExit(main())
