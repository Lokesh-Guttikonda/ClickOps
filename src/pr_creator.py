"""Render the Markdown pull request and open (or refresh) it on GitHub.

The PR branch name is derived from the drift fingerprint, so scheduled runs that see the
same drift update one PR instead of opening duplicates, and a PR that a reviewer closed
without merging (i.e. rejected the ClickOps change) is not reopened.
"""

from __future__ import annotations

import html
import json
import logging
import os
import re
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .cloudtrail_lookup import Attribution
from .hcl_patcher import APPLIED, IN_SYNC, SKIPPED
from .reconciler import ReconcileReport

log = logging.getLogger(__name__)

RISK_BADGE = {
    "none": "⚪",
    "info": "\U0001f535",
    "low": "\U0001f7e2",
    "medium": "\U0001f7e0",
    "high": "\U0001f534",
    "critical": "\U0001f6a8",
}
STATUS_LABEL = {
    APPLIED: "✅ codified",
    IN_SYNC: "☑️ already in code",
    SKIPPED: "⚠️ manual",
}
_SEP = " \u00b7 "
BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"


class PRError(RuntimeError):
    """The pull request could not be created."""


# --------------------------------------------------------------------------- markdown helpers

_MD_SPECIAL = re.compile(r"([\\`*_\[\]|#~])")


def _md(text: Any) -> str:
    """Escape untrusted text (CloudTrail user names, user agents, ...) for Markdown/HTML."""
    text = " ".join(str(text).split())
    text = html.escape(text, quote=False)
    return _MD_SPECIAL.sub(r"\\\1", text).replace("@", "@\u200b")


def _code(value: Any, limit: int = 80) -> str:
    """A code span that is safe inside a GFM table cell."""
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return "`" + text.replace("`", "'").replace("|", "\\|") + "`"


def _value(value: Any, sensitive: bool) -> str:
    if sensitive:
        return "*(sensitive)*"
    if value is None:
        return "*(unset)*"
    return _code(value)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def display_path(path: Path, base_dir: Path | None = None) -> str:
    base = Path(base_dir or Path.cwd()).resolve()
    try:
        return path.resolve().relative_to(base).as_posix()
    except ValueError:
        return path.as_posix()


def _who(attribution: Attribution | None) -> tuple[str, str, str]:
    if attribution is None:
        return "❔ not looked up", "—", "—"
    event = attribution.primary
    if event is None:
        return f"❔ unknown<br><sub>{_md(attribution.note)}</sub>", "—", "—"
    meta = [event.identity_type]
    if event.role_name:
        meta.append(f"role {event.role_name}")
    meta.append(event.channel)
    if event.source_ip:
        meta.append(event.source_ip)
    if event.mfa_authenticated is False:
        meta.append("no MFA")
    who = f"**{_md(event.actor)}**<br><sub>{_SEP.join(_md(m) for m in meta)}</sub>"
    when = event.event_time.strftime("%Y-%m-%d %H:%M:%S")
    what = _code(event.event_name)
    if attribution.confidence != "high":
        what += f"<br><sub>confidence: {attribution.confidence}</sub>"
    return who, when, what


# --------------------------------------------------------------------------- rendering


def render_pr_title(report: ReconcileReport) -> str:
    items = report.drift.actionable_items
    actors = report.actors
    by = f" by {actors[0]}" if len(actors) == 1 else ""
    if len(items) == 1:
        return f"fix(drift): codify ClickOps change to {items[0].address}{by}"
    return f"fix(drift): codify ClickOps changes to {len(items)} resources{by}"


def _render(report: ReconcileReport, base_dir: Path | None, include_diff: bool) -> str:
    items = report.drift.actionable_items
    risk = report.risk
    badge = RISK_BADGE.get(risk, "")
    fingerprint = report.fingerprint
    out: list[str] = []

    if not items:
        out += [
            "## ✅ terradrift-ai: no ClickOps drift",
            "",
            f"Live infrastructure matches the Terraform code ({_md(report.drift.source)}).",
        ]
        return "\n".join(out) + "\n"

    n_changes = sum(len(i.actionable_changes) for i in items)
    workdir = display_path(Path(report.config.workdir), base_dir) or "."
    actors = ", ".join(f"**{_md(a)}**" for a in report.actors)
    detected = report.drift.timestamp or report.generated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    tf_version = f" · Terraform {report.drift.terraform_version}" if report.drift.terraform_version else ""
    files = ", ".join(f"`{display_path(f.path, base_dir)}`" for f in report.patch.files) or "none"

    out += [
        f"## {badge} terradrift-ai: ClickOps drift detected",
        "",
        f"**{_plural(len(items), 'resource')}** changed outside Terraform ({_plural(n_changes, 'attribute')}). "
        "This PR updates the Terraform code to match what is running in AWS, so the manual change is "
        "either **codified** (merge) or **reverted** (close, then `terraform apply`).",
        "",
        "| | |",
        "|---|---|",
        f"| **Risk** | {badge} **{risk.upper()}** |",
        f"| **Changed by** | {actors or chr(0x2754) + ' unknown'} |",
        f"| **Detected** | {_md(detected)}{tf_version} |",
        f"| **CloudTrail** | {_md(report.cloudtrail_source or 'not queried')} |",
        f"| **Patch engine** | {_md(report.patch.engine)} |",
        f"| **Files changed** | {files} |",
        "",
        "### \U0001f50d Audit trail",
        "",
        "| Resource | Attribute | Terraform code | Live in AWS | Changed by | When (UTC) "
        "| CloudTrail event | Code patch |",
        "|---|---|---|---|---|---|---|---|",
    ]
    outcomes = {(o.address, o.change.path if o.change else None): o for o in report.patch.outcomes}
    for item in items:
        who, when, what = _who(report.attributions.get(item.address))
        rows = [None] if item.deleted else item.actionable_changes
        for change in rows:
            outcome = outcomes.get((item.address, change.path if change else None))
            status = STATUS_LABEL.get(outcome.status, "—") if outcome else "—"
            if change is None:
                cells = ["*(entire resource)*", "exists", "**deleted**"]
            else:
                cells = [
                    _code(change.dotted),
                    _value(change.before, change.sensitive),
                    _value(change.after, change.sensitive),
                ]
            out.append(f"| {_code(item.address)} | {' | '.join(cells)} | {who} | {when} | {what} | {status} |")
    out.append("")

    if report.risks:
        out += ["### ⚠️ Risk assessment", ""]
        out += [
            f"- {RISK_BADGE.get(f.level, '')} **{f.level.upper()}** {_code(f.address)}: {f.message}"
            for f in report.risks
        ]
        out.append("")

    if report.patch.ai_notes:
        out += [f"### \U0001f916 AI review ({_md(report.patch.provider)})", ""]
        out += [f"- {note}" for note in report.patch.ai_notes]
        out += ["", "<sub>AI-generated: verify before acting on it.</sub>", ""]

    if report.patch.files:
        out += ["### \U0001f4dd Proposed code change", ""]
        for fp in report.patch.files:
            label = display_path(fp.path, base_dir)
            added, removed = fp.stats()
            if include_diff:
                diff = fp.diff(label).rstrip("\n")
                fence = "````" if "```" in diff else "```"
                out += [
                    f"<details open><summary><code>{html.escape(label)}</code> (+{added} −{removed})</summary>",
                    "",
                    f"{fence}diff",
                    diff,
                    fence,
                    "",
                    "</details>",
                    "",
                ]
            else:
                out.append(f"- `{label}` (+{added} −{removed}): diff omitted (too large), see *Files changed*")
        if not include_diff:
            out.append("")

    if report.patch.suggestions:
        out += [
            "### \U0001f4a1 AI-suggested edits (not applied)",
            "",
            "The LLM proposed these edits, but terradrift-ai could not verify them mechanically, so they are "
            "**not** part of this PR. Apply them by hand if they look right.",
            "",
        ]
        for address, diff in report.patch.suggestions:
            fence = "````" if "```" in diff else "```"
            out += [
                f"<details><summary><code>{html.escape(address)}</code></summary>",
                "",
                f"{fence}diff",
                diff.rstrip("\n"),
                fence,
                "",
                "</details>",
                "",
            ]

    skipped = report.patch.skipped
    if skipped:
        out += ["### ✋ Needs a human", ""]
        for outcome in skipped:
            where = f" {_code(outcome.change.dotted)}" if outcome.change else ""
            out.append(f"- {_code(outcome.address)}{where}: {outcome.reason}")
        out.append("")

    info = [(item, c) for item in report.drift.items for c in item.informational_changes]
    if info:
        out += [
            "<details><summary>ℹ️ State-only drift (no code change needed)</summary>",
            "",
            "| Resource | Attribute | State | Live |",
            "|---|---|---|---|",
        ]
        out += [
            f"| {_code(item.address)} | {_code(c.dotted)} | {_value(c.before, c.sensitive)} | "
            f"{_value(c.after, c.sensitive)} |"
            for item, c in info
        ]
        out += ["", "</details>", ""]

    evidence = [(address, a) for address, a in report.attributions.items() if a.events]
    if evidence:
        out += [
            "<details><summary>\U0001f9fe CloudTrail evidence</summary>",
            "",
            "| Resource | Time (UTC) | Event | Principal | Channel | Source IP | MFA |",
            "|---|---|---|---|---|---|---|",
        ]
        for address, attribution in evidence:
            for event in attribution.events[:5]:
                mfa = {True: "yes", False: "no", None: "—"}[event.mfa_authenticated]
                out.append(
                    f"| {_code(address)} | {event.event_time:%Y-%m-%d %H:%M:%S} | {_code(event.event_name)} | "
                    f"{_md(event.principal_arn or event.actor)} | {_md(event.channel)} | "
                    f"{_md(event.source_ip or chr(0x2014))} | {mfa} |"
                )
        out += ["", "</details>", ""]

    warnings = report.warnings + report.patch.warnings
    if warnings:
        out += ["> [!WARNING]"] + [f"> - {_md(w)}" for w in warnings] + [""]

    out += [
        "### ✅ How to resolve",
        "",
        "- **Merge** if the manual change was intentional: the code now matches AWS and future plans are clean.",
        f"- **Close** to reject it, then run `terraform apply` in `{workdir}` to put AWS back the way the code "
        "describes it. terradrift-ai will not reopen a PR for the same drift.",
    ]
    if actors:
        out.append(f"- Either way, follow up with {actors} so the next change goes through Terraform.")
    out += [
        "",
        f"<sub>Generated by terradrift-ai {__version__} · drift fingerprint <code>{fingerprint}</code></sub>",
        f"<!-- terradrift:fingerprint={fingerprint} -->",
    ]
    return "\n".join(out) + "\n"


def render_pr_body(report: ReconcileReport, *, base_dir: Path | None = None, max_length: int = 60000) -> str:
    """Markdown PR description. GitHub caps bodies at 65,536 characters."""
    body = _render(report, base_dir, include_diff=True)
    if len(body) > max_length:
        body = _render(report, base_dir, include_diff=False)
    if len(body) > max_length:
        marker = f"<!-- terradrift:fingerprint={report.fingerprint} -->"
        body = (
            body[: max_length - 200] + "\n\n*(truncated: see the workflow log for the full report)*\n" + marker + "\n"
        )
    return body


def render_commit_message(report: ReconcileReport) -> tuple[str, str]:
    lines = []
    for item in report.drift.actionable_items:
        attribution = report.attributions.get(item.address)
        who = (
            f" (by {attribution.primary.actor} via {attribution.primary.event_name})"
            if attribution and attribution.primary
            else ""
        )
        for change in item.actionable_changes:
            if change.sensitive:
                lines.append(f"- {item.address}.{change.dotted}: (sensitive){who}")
            else:
                lines.append(
                    f"- {item.address}.{change.dotted}: {json.dumps(change.before, default=str)} -> "
                    f"{json.dumps(change.after, default=str)}{who}"
                )
    lines += ["", f"terradrift-fingerprint: {report.fingerprint}"]
    return render_pr_title(report), "\n".join(lines)


# --------------------------------------------------------------------------- GitHub


def repo_slug_from_remote(url: str) -> str | None:
    """``git@github.com:o/r.git`` / ``https://github.com/o/r`` -> ``o/r``."""
    match = re.search(r"[:/]([^/:]+)/([^/]+?)(?:\.git)?/?$", url.strip())
    return f"{match.group(1)}/{match.group(2)}" if match else None


class GitHubClient:
    def __init__(self, token: str, repo: str, *, api_url: str | None = None, transport: Any = None) -> None:
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover
            raise PRError("opening pull requests needs httpx: pip install httpx") from exc
        self.repo = repo
        self._client = httpx.Client(
            base_url=(api_url or os.environ.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/"),
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": f"terradrift-ai/{__version__}",
            },
            timeout=30,
            transport=transport,
        )

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        response = self._client.request(method, path, **kwargs)
        if response.status_code >= 400:
            try:
                message = response.json().get("message", "")
            except ValueError:
                message = response.text[:200]
            raise PRError(f"GitHub API {method} {path} returned {response.status_code}: {message}")
        return response.json() if response.content else None

    def default_branch(self) -> str:
        return self._request("GET", f"/repos/{self.repo}")["default_branch"]

    def find_pulls(self, branch: str) -> list[dict[str, Any]]:
        owner = self.repo.split("/")[0]
        return self._request(
            "GET", f"/repos/{self.repo}/pulls", params={"head": f"{owner}:{branch}", "state": "all", "per_page": 20}
        )

    def create_pull(self, *, title: str, body: str, head: str, base: str, draft: bool) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/repos/{self.repo}/pulls",
            json={"title": title, "body": body, "head": head, "base": base, "draft": draft},
        )

    def update_pull(self, number: int, *, title: str, body: str) -> dict[str, Any]:
        return self._request("PATCH", f"/repos/{self.repo}/pulls/{number}", json={"title": title, "body": body})

    def add_labels(self, number: int, labels: Sequence[str]) -> None:
        self._request("POST", f"/repos/{self.repo}/issues/{number}/labels", json={"labels": list(labels)})


GitRunner = Callable[[Sequence[str], Path], str]


def run_git(args: Sequence[str], cwd: Path) -> str:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise PRError(f"git {' '.join(args)} failed: {(proc.stderr or proc.stdout).strip()}")
    return proc.stdout.strip()


@dataclass
class PullRequestResult:
    action: str  # created | updated | skipped
    url: str | None
    number: int | None
    branch: str
    message: str = ""


def open_or_update_pull_request(
    report: ReconcileReport,
    *,
    repo_root: str | os.PathLike[str] | None = None,
    token: str | None = None,
    repo: str | None = None,
    base: str | None = None,
    labels: Sequence[str] = (),
    draft: bool = False,
    branch_prefix: str = "terradrift/drift-",
    github: GitHubClient | None = None,
    git: GitRunner = run_git,
) -> PullRequestResult:
    """Commit the patched files (already written in place) to a branch and open a PR."""
    if not report.patch.files:
        return PullRequestResult("skipped", None, None, "", "no code changes to propose")
    root = Path(repo_root) if repo_root else Path(git(["rev-parse", "--show-toplevel"], Path.cwd()))
    if github is None:
        token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if not token:
            raise PRError("set GITHUB_TOKEN (or GH_TOKEN) to open pull requests")
        repo = (
            repo
            or os.environ.get("GITHUB_REPOSITORY")
            or repo_slug_from_remote(git(["remote", "get-url", "origin"], root))
        )
        if not repo:
            raise PRError("could not determine owner/repo; set GITHUB_REPOSITORY")
        github = GitHubClient(token, repo)

    branch = branch_prefix + report.fingerprint[:10]
    title, commit_body = render_commit_message(report)
    body = render_pr_body(report, base_dir=root)

    existing = github.find_pulls(branch) or []
    open_pr = next((p for p in existing if p.get("state") == "open"), None)
    if open_pr:
        github.update_pull(open_pr["number"], title=title, body=body)
        return PullRequestResult(
            "updated", open_pr.get("html_url"), open_pr.get("number"), branch, "a PR for this drift is already open"
        )
    closed = next((p for p in existing if p.get("state") == "closed"), None)
    if closed:
        message = (
            "this drift was already codified by a merged PR"
            if closed.get("merged_at")
            else "a PR for this exact drift was closed without merging (rejected): run `terraform apply` to revert"
        )
        return PullRequestResult("skipped", closed.get("html_url"), closed.get("number"), branch, message)

    base = base or os.environ.get("TERRADRIFT_BASE_BRANCH") or github.default_branch()
    files = []
    for fp in report.patch.files:
        try:
            files.append(fp.path.resolve().relative_to(root.resolve()).as_posix())
        except ValueError as exc:
            raise PRError(f"{fp.path} is outside the repository {root}") from exc

    try:
        git(["config", "user.email"], root)
        identity: list[str] = []
    except PRError:
        identity = ["-c", f"user.name={BOT_NAME}", "-c", f"user.email={BOT_EMAIL}"]
    original = git(["rev-parse", "--abbrev-ref", "HEAD"], root)
    if original == "HEAD":
        original = git(["rev-parse", "HEAD"], root)

    git(["checkout", "-B", branch], root)
    try:
        git(["add", "--", *files], root)
        git([*identity, "commit", "-m", title, "-m", commit_body], root)
        # The branch name is derived from the drift itself and owned by terradrift.
        git(["push", "--force", "-u", "origin", branch], root)
    finally:
        try:
            git(["checkout", original], root)
        except PRError as exc:
            log.warning("could not switch back to %s: %s", original, exc)

    pr = github.create_pull(title=title, body=body, head=branch, base=base, draft=draft)
    if labels:
        try:
            github.add_labels(pr["number"], labels)
        except PRError as exc:
            log.warning("could not add labels: %s", exc)
    return PullRequestResult("created", pr.get("html_url"), pr.get("number"), branch)
