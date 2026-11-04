from __future__ import annotations

import json

import pytest

from src.cli import EXIT_DRIFT, EXIT_ERROR, EXIT_OK, main
from src.pr_creator import PullRequestResult


def reconcile_args(workdir, *extra):
    return [
        "reconcile",
        "-C",
        str(workdir),
        "--plan-json",
        str(workdir / "drifted_plan.json"),
        "--cloudtrail-events",
        str(workdir / "cloudtrail_events.json"),
        "--no-color",
        *extra,
    ]


def test_dry_run_prints_the_diff_and_writes_nothing(example_workdir, capsys):
    before = (example_workdir / "main.tf").read_text()
    assert main(reconcile_args(example_workdir, "--dry-run")) == EXIT_OK
    out = capsys.readouterr().out
    assert "terradrift-ai: 1 resource(s) changed outside Terraform (risk: MEDIUM)" in out
    assert "~ ingress[0].from_port: 443 -> 8443  [codified]" in out
    assert "changed by admin-hotfix (IAMUser, AWS Console, 203.0.113.42) via ModifySecurityGroupRules" in out
    assert "+    from_port   = 8443" in out
    assert (example_workdir / "main.tf").read_text() == before


def test_reconcile_writes_in_place_and_emits_github_outputs(example_workdir, tmp_path, monkeypatch, capsys):
    outputs, summary = tmp_path / "gh_output", tmp_path / "step_summary.md"
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    md, js = tmp_path / "pr.md", tmp_path / "report.json"

    code = main(reconcile_args(example_workdir, "--summary-file", str(md), "--json-file", str(js)))

    assert code == EXIT_OK
    assert "from_port   = 8443" in (example_workdir / "main.tf").read_text()
    lines = dict(line.split("=", 1) for line in outputs.read_text().splitlines())
    assert lines["drift-detected"] == "true" and lines["risk"] == "medium"
    assert lines["changed-files"].endswith("main.tf") and lines["pr-url"] == ""
    assert "Audit trail" in md.read_text(encoding="utf-8")
    assert "Audit trail" in summary.read_text(encoding="utf-8")
    assert json.loads(js.read_text())["attributions"]["aws_security_group.web"]["primary"]["actor"] == "admin-hotfix"


def test_output_dir_mirrors_patched_files(example_workdir, tmp_path):
    out = tmp_path / "patched"
    assert main(reconcile_args(example_workdir, "--output-dir", str(out))) == EXIT_OK
    assert "from_port   = 8443" in (out / "main.tf").read_text()
    assert "= 8443" not in (example_workdir / "main.tf").read_text()


def test_fail_on_drift(example_workdir):
    assert main(reconcile_args(example_workdir, "--dry-run", "--fail-on-drift")) == EXIT_DRIFT
    assert main(["detect", "--plan-json", str(example_workdir / "drifted_plan.json"), "--fail-on-drift"]) == EXIT_DRIFT


def test_detect_json(example_workdir, capsys):
    assert main(["detect", "--plan-json", str(example_workdir / "drifted_plan.json"), "--json"]) == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["has_drift"] is True
    assert data["items"][0]["changes"][0] == {
        "path": "ingress[0].from_port",
        "before": 443,
        "after": 8443,
        "kind": "modified",
        "sensitive": False,
        "actionable": True,
    }


def test_detect_text(example_workdir, capsys):
    main(["detect", "--plan-json", str(example_workdir / "drifted_plan.json")])
    assert capsys.readouterr().out.splitlines()[:2] == [
        "aws_security_group.web",
        "  ~ ingress[0].from_port: 443 -> 8443",
    ]


def test_create_pr_hands_over_to_the_pr_creator(example_workdir, monkeypatch, capsys):
    calls = {}

    def fake_open(report, **kwargs):
        calls.update(kwargs, report=report)
        return PullRequestResult("created", "https://github.com/o/r/pull/9", 9, "terradrift/drift-x")

    monkeypatch.setattr("src.cli.open_or_update_pull_request", fake_open)
    code = main(reconcile_args(example_workdir, "--create-pr", "--label", "drift", "--base", "main", "--draft"))
    assert code == EXIT_OK
    assert calls["labels"] == ["drift"] and calls["base"] == "main" and calls["draft"] is True
    assert "pull request created: https://github.com/o/r/pull/9" in capsys.readouterr().out


def test_create_pr_cannot_be_combined_with_dry_run(example_workdir):
    with pytest.raises(SystemExit) as exc:
        main(reconcile_args(example_workdir, "--create-pr", "--dry-run"))
    assert exc.value.code == 2


@pytest.mark.parametrize(
    ("args", "env", "message"),
    [
        (["detect", "--plan-json", "does-not-exist.json"], {}, "No such file"),
        (None, {"PROVIDER": "grok"}, "unknown PROVIDER"),
    ],
)
def test_errors_exit_1_with_a_message(example_workdir, monkeypatch, capsys, args, env, message):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert main(args or reconcile_args(example_workdir, "--dry-run")) == EXIT_ERROR
    assert message in capsys.readouterr().err


def test_no_drift(example_workdir, tmp_path, capsys):
    clean = tmp_path / "clean.json"
    clean.write_text(json.dumps({"format_version": "1.2", "resource_drift": [], "resource_changes": []}))
    assert main(["reconcile", "-C", str(example_workdir), "--plan-json", str(clean), "--no-color"]) == EXIT_OK
    assert "no ClickOps drift" in capsys.readouterr().out


def test_version(capsys):
    with pytest.raises(SystemExit):
        main(["--version"])
    assert "terradrift-ai 0.1.0" in capsys.readouterr().out
