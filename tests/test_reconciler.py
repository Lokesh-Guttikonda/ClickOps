"""End-to-end: the whole pipeline, offline, exactly as `python scripts/demo_offline.py` runs it."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

import pytest

from src import detector
from src.cloudtrail_lookup import CloudTrailError
from src.detector import TerraformError, detect_drift
from src.reconciler import ReconcileConfig, reconcile
from src.risk import assess_item

from .conftest import EXAMPLES, ROOT
from .helpers import drift_item, make_plan, resource_entry, security_group, sg_rule


def config_for(workdir, **overrides) -> ReconcileConfig:
    settings = dict(
        workdir=workdir,
        plan_json=workdir / "drifted_plan.json",
        cloudtrail="mock",
        cloudtrail_events=workdir / "cloudtrail_events.json",
    )
    settings.update(overrides)
    return ReconcileConfig(**settings)


def test_full_pipeline_detects_attributes_patches_and_reports(example_workdir):
    report = reconcile(config_for(example_workdir))

    # detect
    assert report.has_drift
    [item] = report.drift.actionable_items
    assert item.address == "aws_security_group.web"
    # who
    attribution = report.attributions[item.address]
    assert report.actors == ["admin-hotfix"]
    assert attribution.primary.event_name == "ModifySecurityGroupRules"
    assert attribution.primary.event_time.isoformat() == "2026-11-03T22:47:12+00:00"
    # patch
    [fp] = report.patch.files
    assert "from_port   = 8443" in fp.patched and "to_port     = 8443" in fp.patched
    assert fp.original == (example_workdir / "main.tf").read_text(), "reconcile() never writes files"
    # risk
    assert report.risk == "medium"
    # machine-readable report
    data = json.loads(json.dumps(report.to_dict(), default=str))
    assert data["has_drift"] is True and data["risk"] == "medium"
    assert data["attributions"]["aws_security_group.web"]["primary"]["actor"] == "admin-hotfix"
    assert data["patch"]["outcomes"][0]["status"] == "applied"


def test_fingerprint_is_stable_and_tracks_the_drift(example_workdir):
    first = reconcile(config_for(example_workdir)).fingerprint
    assert reconcile(config_for(example_workdir)).fingerprint == first
    plan = json.loads((example_workdir / "drifted_plan.json").read_text())
    plan["resource_drift"][0]["change"]["after"]["ingress"][0]["from_port"] = 9443
    (example_workdir / "other.json").write_text(json.dumps(plan))
    assert reconcile(config_for(example_workdir, plan_json=example_workdir / "other.json")).fingerprint != first


def test_clean_plans_report_no_drift(example_workdir):
    (example_workdir / "clean.json").write_text(json.dumps(make_plan()))
    report = reconcile(config_for(example_workdir, plan_json=example_workdir / "clean.json"))
    assert not report.has_drift and report.risk == "none" and report.patch.files == []
    assert report.attributions == {}


def test_cloudtrail_failures_are_warnings_not_errors(example_workdir):
    class Broken:
        name = label = "broken"

        def lookup(self, *args):
            raise CloudTrailError("AccessDenied: cloudtrail:LookupEvents")

    report = reconcile(config_for(example_workdir), cloudtrail_backend=Broken())
    assert report.patch.files, "the code is still patched"
    assert any("AccessDenied" in w for w in report.warnings)


def test_cloudtrail_can_be_turned_off(example_workdir):
    report = reconcile(config_for(example_workdir, cloudtrail="off"))
    assert report.attributions == {} and report.cloudtrail_source is None and report.patch.files


def test_runs_terraform_when_no_plan_file_is_given(example_workdir, monkeypatch):
    monkeypatch.setattr(detector.shutil, "which", lambda name: "/usr/bin/terraform")
    plan_json = (example_workdir / "drifted_plan.json").read_text()

    def fake_terraform(cmd, cwd=None, **kwargs):
        if cmd[1] == "plan":
            return subprocess.CompletedProcess(cmd, 2, "", "")
        return subprocess.CompletedProcess(cmd, 0, plan_json, "")

    report = reconcile(config_for(example_workdir, plan_json=None), terraform_runner=fake_terraform)
    assert report.has_drift and report.drift.source.startswith("terraform plan")

    def broken(cmd, cwd=None, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, "", "Error: No valid credential sources found")

    with pytest.raises(TerraformError, match="credential"):
        reconcile(config_for(example_workdir, plan_json=None), terraform_runner=broken)


@pytest.mark.parametrize(
    ("port", "cidr", "level", "words"),
    [
        (22, "0.0.0.0/0", "high", "SSH (22)"),
        (8443, "0.0.0.0/0", "medium", "non-standard port"),
        (5432, "10.0.0.0/8", "low", "ingress rule changed"),
    ],
)
def test_risk_rules_for_security_groups(port, cidr, level, words):
    https = sg_rule("HTTPS", 443)
    live = {**https, "from_port": port, "to_port": port, "cidr_blocks": [cidr]}
    [finding] = assess_item(drift_item("aws_security_group.web", security_group([https]), security_group([live])))
    assert finding.level == level and words in finding.message


def test_risk_rules_for_all_traffic_and_deletions():
    https = sg_rule("HTTPS", 443)
    everything = sg_rule("debug", 0, "-1")
    [finding] = assess_item(
        drift_item("aws_security_group.web", security_group([https]), security_group([https, everything]))
    )
    assert finding.level == "critical"
    state = security_group([https])
    plan = make_plan([resource_entry("aws_security_group.web", state, None, actions=("delete",))])
    [finding] = assess_item(detect_drift(plan).items[0])
    assert finding.level == "high" and "deleted" in finding.message


# --------------------------------------------------------------------------- the demo script


def _demo_env() -> dict:
    env = {k: v for k, v in os.environ.items() if not k.endswith(("_API_KEY", "_TOKEN"))}
    env.pop("PROVIDER", None)
    env["NO_COLOR"] = "1"
    return env


def test_demo_script_runs_offline_and_leaves_examples_untouched(tmp_path):
    before = (EXAMPLES / "main.tf").read_text()
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "demo_offline.py"), "--output-dir", str(tmp_path)],
        capture_output=True,
        text=True,
        env=_demo_env(),
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    for expected in (
        "[1/4] Detect drift",
        "ingress[0].from_port: 443 -> 8443",
        "who:        admin-hotfix",
        "ModifySecurityGroupRules at 2026-11-03 22:47:12 UTC",
        "+    from_port   = 8443",
        "title: fix(drift): codify ClickOps change to aws_security_group.web by admin-hotfix",
        "### \U0001f50d Audit trail",
    ):
        assert expected in out, f"missing {expected!r} in demo output"
    assert "from_port   = 8443" in (tmp_path / "main.tf").read_text()
    assert "Audit trail" in (tmp_path / "PR_SUMMARY.md").read_text(encoding="utf-8")
    assert json.loads((tmp_path / "report.json").read_text())["risk"] == "medium"
    assert (EXAMPLES / "main.tf").read_text() == before


def test_demo_needs_no_third_party_packages(tmp_path):
    """PROVIDER=mock must work on a bare Python install (no httpx)."""
    script = (
        "import runpy, sys; sys.modules['httpx'] = None; "
        f"sys.argv = ['demo', '--output-dir', {str(tmp_path)!r}, '--quiet']; "
        f"runpy.run_path({str(ROOT / 'scripts' / 'demo_offline.py')!r}, run_name='__main__')"
    )
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, env=_demo_env(), timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert "admin-hotfix" in proc.stdout


def test_demo_in_place_patches_examples_main_tf(tmp_path):
    work = tmp_path / "repo"
    shutil.copytree(ROOT / "scripts", work / "scripts")
    shutil.copytree(ROOT / "src", work / "src", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(EXAMPLES, work / "examples")
    proc = subprocess.run(
        [sys.executable, str(work / "scripts" / "demo_offline.py"), "--in-place", "--quiet"],
        capture_output=True,
        text=True,
        env=_demo_env(),
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert "from_port   = 8443" in (work / "examples" / "main.tf").read_text()
