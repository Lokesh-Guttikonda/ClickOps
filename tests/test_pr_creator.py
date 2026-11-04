from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from src.cloudtrail_lookup import Attribution
from src.pr_creator import (
    GitHubClient,
    PRError,
    open_or_update_pull_request,
    render_commit_message,
    render_pr_body,
    render_pr_title,
    repo_slug_from_remote,
)
from src.reconciler import ReconcileConfig, reconcile


@pytest.fixture
def report(example_workdir):
    return reconcile(
        ReconcileConfig(
            workdir=example_workdir,
            plan_json=example_workdir / "drifted_plan.json",
            cloudtrail="mock",
            cloudtrail_events=example_workdir / "cloudtrail_events.json",
        )
    )


def test_title_and_commit_message(report):
    assert render_pr_title(report) == "fix(drift): codify ClickOps change to aws_security_group.web by admin-hotfix"
    title, body = render_commit_message(report)
    assert title == render_pr_title(report)
    assert (
        "- aws_security_group.web.ingress[0].from_port: 443 -> 8443 (by admin-hotfix via ModifySecurityGroupRules)"
        in body
    )
    assert f"terradrift-fingerprint: {report.fingerprint}" in body


def test_body_has_the_audit_table_risk_and_diff(report, example_workdir):
    body = render_pr_body(report, base_dir=example_workdir.parent)
    assert "## \U0001f7e0 terradrift-ai: ClickOps drift detected" in body
    assert (
        "| `aws_security_group.web` | `ingress[0].from_port` | `443` | `8443` | "
        "**admin-hotfix**<br><sub>IAMUser · AWS Console · 203.0.113.42</sub> | 2026-11-03 22:47:12 | "
        "`ModifySecurityGroupRules` | ✅ codified |"
    ) in body
    assert (
        "**MEDIUM** `aws_security_group.web`: ingress now allows tcp/8443 from 0.0.0.0/0 (previously tcp/443)" in body
    )
    assert "```diff\n--- a/infra/main.tf\n+++ b/infra/main.tf" in body
    assert "+    from_port   = 8443" in body
    assert "`terraform apply` in `infra`" in body
    assert body.rstrip().endswith(f"<!-- terradrift:fingerprint={report.fingerprint} -->")


def test_untrusted_cloudtrail_values_are_escaped(report):
    attribution = report.attributions["aws_security_group.web"]
    evil = dataclasses.replace(
        attribution.primary,
        actor="<img src=x onerror=alert(1)>|@octocat",
        user_agent="[click](javascript:alert(1))",
        via_console=False,
    )
    report.attributions["aws_security_group.web"] = dataclasses.replace(attribution, primary=evil, events=[evil])
    body = render_pr_body(report)
    assert "<img" not in body
    assert "@octocat" not in body and "@​octocat" in body
    assert "&lt;img src=x onerror=alert(1)&gt;\\|" in body
    assert "](javascript:" not in body


def test_long_bodies_drop_the_diff_first_then_truncate(report):
    full = render_pr_body(report)
    without_diff = render_pr_body(report, max_length=len(full) - 1)
    assert "```diff" not in without_diff and "diff omitted (too large)" in without_diff
    tiny = render_pr_body(report, max_length=1000)
    assert len(tiny) <= 1000 and "truncated" in tiny
    assert tiny.rstrip().endswith(f"<!-- terradrift:fingerprint={report.fingerprint} -->")


def test_unattributed_drift_says_so(report):
    report.attributions["aws_security_group.web"] = Attribution(
        "aws_security_group.web", "sg-1", [], None, "none", "no ClickOps events for this resource in the last 168h"
    )
    body = render_pr_body(report)
    assert "❔ unknown<br><sub>no ClickOps events for this resource in the last 168h</sub>" in body
    assert render_pr_title(report).endswith("aws_security_group.web")


def test_no_drift_body(report):
    report.drift.items = []
    assert "no ClickOps drift" in render_pr_body(report)


@pytest.mark.parametrize(
    ("url", "slug"),
    [
        ("https://github.com/Lokesh-Guttikonda/ClickOps.git", "Lokesh-Guttikonda/ClickOps"),
        ("git@github.com:octo/infra.git", "octo/infra"),
        ("https://x-access-token:abc@github.example.com/team/repo/", "team/repo"),
        ("not a url", None),
    ],
)
def test_repo_slug_from_remote(url, slug):
    assert repo_slug_from_remote(url) == slug


# --------------------------------------------------------------------------- opening the PR


class FakeGit:
    def __init__(self, root: Path, has_identity: bool = False):
        self.root = root
        self.has_identity = has_identity
        self.calls: list[list[str]] = []

    def __call__(self, args, cwd):
        args = list(args)
        self.calls.append(args)
        if args == ["config", "user.email"]:
            if not self.has_identity:
                raise PRError("git config user.email failed")
            return "me@example.com"
        if args == ["rev-parse", "--abbrev-ref", "HEAD"]:
            return "main"
        if args == ["rev-parse", "--show-toplevel"]:
            return str(self.root)
        return ""


class FakeGitHub:
    def __init__(self, pulls=()):
        self.pulls = list(pulls)
        self.created: list[dict] = []
        self.updated: list[tuple] = []
        self.labels: list[tuple] = []

    def find_pulls(self, branch):
        self.branch = branch
        return self.pulls

    def default_branch(self):
        return "main"

    def create_pull(self, **kwargs):
        self.created.append(kwargs)
        return {"number": 42, "html_url": "https://github.com/o/r/pull/42"}

    def update_pull(self, number, **kwargs):
        self.updated.append((number, kwargs))
        return {}

    def add_labels(self, number, labels):
        self.labels.append((number, list(labels)))


def test_creates_a_branch_commit_and_pull_request(report, example_workdir):
    report.patch.write()
    git, gh = FakeGit(example_workdir.parent), FakeGitHub()
    result = open_or_update_pull_request(
        report, repo_root=example_workdir.parent, github=gh, git=git, labels=["drift", "clickops"]
    )
    branch = f"terradrift/drift-{report.fingerprint[:10]}"
    assert (result.action, result.number, result.branch) == ("created", 42, branch)
    commit = next(c for c in git.calls if "commit" in c)
    assert commit[:4] == [
        "-c",
        "user.name=github-actions[bot]",
        "-c",
        "user.email=41898282+github-actions[bot]@users.noreply.github.com",
    ]
    assert ["checkout", "-B", branch] in git.calls
    assert ["add", "--", "infra/main.tf"] in git.calls
    assert ["push", "--force", "-u", "origin", branch] in git.calls
    assert git.calls[-1] == ["checkout", "main"], "switches back to the original branch"
    [created] = gh.created
    assert created["head"] == branch and created["base"] == "main" and created["draft"] is False
    assert "Audit trail" in created["body"]
    assert gh.labels == [(42, ["drift", "clickops"])]


def test_an_open_pr_for_the_same_drift_is_refreshed(report, example_workdir):
    git = FakeGit(example_workdir.parent, has_identity=True)
    gh = FakeGitHub([{"number": 7, "state": "open", "html_url": "https://github.com/o/r/pull/7"}])
    result = open_or_update_pull_request(report, repo_root=example_workdir.parent, github=gh, git=git)
    assert (result.action, result.number) == ("updated", 7)
    assert gh.updated[0][0] == 7 and not gh.created
    assert not any("commit" in c for c in git.calls)


@pytest.mark.parametrize(("merged_at", "message"), [(None, "rejected"), ("2026-11-04T07:00:00Z", "merged")])
def test_closed_prs_are_not_reopened(report, example_workdir, merged_at, message):
    gh = FakeGitHub([{"number": 3, "state": "closed", "merged_at": merged_at, "html_url": "u"}])
    result = open_or_update_pull_request(
        report, repo_root=example_workdir.parent, github=gh, git=FakeGit(example_workdir.parent)
    )
    assert result.action == "skipped" and message in result.message and not gh.created


def test_nothing_to_propose(report):
    report.patch.files = []
    assert open_or_update_pull_request(report, repo_root=Path("."), github=FakeGitHub()).action == "skipped"


def test_a_token_is_required(report, example_workdir):
    with pytest.raises(PRError, match="GITHUB_TOKEN"):
        open_or_update_pull_request(report, repo_root=example_workdir.parent, git=FakeGit(example_workdir.parent))


def test_github_client_requests():
    httpx = pytest.importorskip("httpx")
    seen = []

    def handler(request):
        seen.append(request)
        if request.method == "GET" and request.url.path == "/repos/o/r/pulls":
            return httpx.Response(200, json=[])
        if request.method == "POST" and request.url.path == "/repos/o/r/pulls":
            return httpx.Response(201, json={"number": 1, "html_url": "https://github.com/o/r/pull/1"})
        if request.url.path == "/repos/o/r":
            return httpx.Response(200, json={"default_branch": "trunk"})
        return httpx.Response(404, json={"message": "Not Found"})

    client = GitHubClient("ghs_token", "o/r", transport=httpx.MockTransport(handler))
    assert client.find_pulls("terradrift/drift-abc") == []
    assert seen[0].url.params["head"] == "o:terradrift/drift-abc"
    assert seen[0].headers["authorization"] == "Bearer ghs_token"
    assert seen[0].headers["x-github-api-version"] == "2022-11-28"
    assert client.default_branch() == "trunk"
    assert client.create_pull(title="t", body="b", head="h", base="trunk", draft=True)["number"] == 1
    assert json.loads(seen[-1].content)["draft"] is True
    with pytest.raises(PRError, match="404: Not Found"):
        client.update_pull(9, title="t", body="b")
