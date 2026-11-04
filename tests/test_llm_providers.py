"""Groq / Gemini / Anthropic modes, exercised against an in-process fake (httpx.MockTransport)."""

from __future__ import annotations

import json

import pytest

httpx = pytest.importorskip("httpx")

from src import hcl  # noqa: E402
from src.detector import DriftReport, detect_drift  # noqa: E402
from src.hcl_patcher import (  # noqa: E402
    APPLIED,
    PATCH_SYSTEM,
    REVIEW_SYSTEM,
    SKIPPED,
    ConfigError,
    build_patch_prompt,
    get_patcher,
    sanitize_note,
)

from .conftest import EXAMPLES  # noqa: E402
from .helpers import drift_item, security_group, sg_rule  # noqa: E402

REVIEW = "- Port 8443 is now open to the internet; confirm with @admin-hotfix.\n- <b>Check</b> the WAF.\n"


class FakeAPI:
    """Replays canned responses and records every request."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        return reply(request) if callable(reply) else reply

    @property
    def bodies(self) -> list[dict]:
        return [json.loads(r.content) for r in self.requests]

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)


def chat(content: str) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": content}}]})


def claude(text: str, stop: str = "end_turn", **extra) -> httpx.Response:
    content = [{"type": "thinking", "thinking": ""}, {"type": "text", "text": text}]
    return httpx.Response(200, json={"content": content, "stop_reason": stop, **extra})


def example_block(replacements: dict[str, str] | None = None) -> str:
    text = (EXAMPLES / "main.tf").read_text()
    block = hcl.find_resource(hcl.parse(text), "aws_security_group", "web")
    block_text = text[block.start : block.close_brace + 1]
    for old, new in (replacements or {}).items():
        assert old in block_text
        block_text = block_text.replace(old, new)
    return block_text


FIXED = {"from_port   = 443\n    to_port     = 443": "from_port   = 8443\n    to_port     = 8443"}


def patcher_for(provider: str, api: FakeAPI, sleeps: list | None = None, **env):
    keys = {"groq": "GROQ_API_KEY", "gemini": "GEMINI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}
    env = {keys[provider]: "test-key", **env}
    sleep = sleeps.append if sleeps is not None else (lambda seconds: None)
    return get_patcher(provider, env=env, transport=api.transport(), sleep=sleep)


# --------------------------------------------------------------------------- configuration


def test_mock_is_the_default_and_never_builds_a_client():
    patcher = get_patcher(env={})
    assert patcher.provider == "mock" and patcher.llm is None
    assert patcher.engine == "rules (deterministic, offline)"
    assert get_patcher(env={"PROVIDER": "MOCK"}).provider == "mock"


def test_unknown_providers_are_rejected():
    with pytest.raises(ConfigError, match="grok"):
        get_patcher(env={"PROVIDER": "grok"})
    with pytest.raises(ConfigError, match="LLM_PATCH_MODE"):
        get_patcher("groq", env={"GROQ_API_KEY": "k", "LLM_PATCH_MODE": "sometimes"})


@pytest.mark.parametrize(
    ("provider", "key"), [("groq", "GROQ_API_KEY"), ("gemini", "GEMINI_API_KEY"), ("anthropic", "ANTHROPIC_API_KEY")]
)
def test_missing_api_keys_fall_back_to_the_rules_engine(provider, key, example_plan, example_workdir):
    patcher = get_patcher(provider, env={})
    assert patcher.llm is None
    result = patcher.patch(detect_drift(example_plan), example_workdir)
    assert [o.status for o in result.outcomes] == [APPLIED, APPLIED]
    assert any(key in w for w in result.warnings)


# --------------------------------------------------------------------------- OpenAI-compatible


def test_groq_reviews_the_drift_and_never_sees_identities(example_plan, example_workdir):
    api = FakeAPI(chat(REVIEW))
    result = patcher_for("groq", api).patch(detect_drift(example_plan), example_workdir)

    # the rules engine handled both changes, so the only call is the review
    [request] = api.requests
    assert str(request.url) == "https://api.groq.com/openai/v1/chat/completions"
    assert request.headers["authorization"] == "Bearer test-key"
    body = api.bodies[0]
    assert body["model"] == "llama-3.3-70b-versatile" and body["temperature"] == 0
    assert body["messages"][0] == {"role": "system", "content": REVIEW_SYSTEM}
    prompt = body["messages"][1]["content"]
    assert "ingress[0].from_port: 443 -> 8443" in prompt
    for secret in ("admin-hotfix", "203.0.113.42", "test-key"):
        assert secret not in prompt

    assert [(o.status, o.engine) for o in result.outcomes] == [(APPLIED, "rules"), (APPLIED, "rules")]
    assert result.ai_notes == [
        "Port 8443 is now open to the internet; confirm with @​admin-hotfix.",
        "&lt;b&gt;Check&lt;/b&gt; the WAF.",
    ]
    assert result.engine.startswith("rules + groq `llama-3.3-70b-versatile`")


def test_gemini_and_custom_openai_compatible_endpoints(example_plan, example_workdir):
    api = FakeAPI(chat(REVIEW))
    patcher_for("gemini", api, LLM_MODEL="gemini-2.5-pro").patch(detect_drift(example_plan), example_workdir)
    assert str(api.requests[0].url) == "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
    assert api.bodies[0]["model"] == "gemini-2.5-pro"

    local = FakeAPI(chat(REVIEW))
    patcher_for("groq", local, LLM_BASE_URL="http://localhost:11434/v1/").patch(
        detect_drift(example_plan), example_workdir
    )
    assert str(local.requests[0].url) == "http://localhost:11434/v1/chat/completions"


def test_always_mode_accepts_a_valid_llm_patch(example_plan, example_workdir):
    api = FakeAPI(chat(f"```hcl\n{example_block(FIXED)}\n```\nNOTES:\n- none\n"), chat(REVIEW))
    result = patcher_for("groq", api, LLM_PATCH_MODE="always").patch(detect_drift(example_plan), example_workdir)

    assert api.bodies[0]["messages"][0]["content"] == PATCH_SYSTEM
    assert 'resource "aws_security_group" "web"' in api.bodies[0]["messages"][1]["content"]
    assert result.warnings == []
    assert [(o.status, o.engine) for o in result.outcomes] == [(APPLIED, "llm:groq"), (APPLIED, "llm:groq")]
    [fp] = result.files
    assert "from_port   = 8443" in fp.patched and "to_port     = 8443" in fp.patched


@pytest.mark.parametrize(
    ("reply", "error"),
    [
        (f"```hcl\n{example_block({**FIXED, 'web-tier-sg': 'renamed'})}\n```", "modified `name`"),
        (f"```hcl\n{example_block({'from_port   = 443': 'from_port   = 8443'})}\n```", "ingress[0].to_port"),
        ("Sure! Here is the change you asked for.", "did not contain"),
        ('```hcl\nresource "aws_security_group" "other" {\n}\n```', "exactly one"),
        ('```hcl\nresource "aws_security_group" "web" {\n```', "does not parse"),
    ],
)
def test_bad_llm_patches_are_rejected_and_the_rules_result_is_kept(reply, error, example_plan, example_workdir):
    api = FakeAPI(chat(reply), chat(REVIEW))
    result = patcher_for("groq", api, LLM_PATCH_MODE="always").patch(detect_drift(example_plan), example_workdir)
    assert any(error in w and "kept the deterministic result" in w for w in result.warnings), result.warnings
    assert [(o.status, o.engine) for o in result.outcomes] == [(APPLIED, "rules"), (APPLIED, "rules")]
    assert "from_port   = 8443" in result.files[0].patched and "renamed" not in result.files[0].patched


def test_fallback_mode_lets_the_llm_fix_what_the_rules_cannot(tmp_path):
    (tmp_path / "main.tf").write_text('resource "aws_instance" "web" { monitoring = true }\n')
    item = drift_item("aws_instance.web", {"id": "i-1", "monitoring": True}, {"id": "i-1", "monitoring": None})
    api = FakeAPI(chat('```hcl\nresource "aws_instance" "web" {\n}\n```'), chat(REVIEW))
    result = patcher_for("groq", api).patch(DriftReport(items=[item]), tmp_path)
    [outcome] = result.outcomes
    assert (outcome.status, outcome.engine) == (APPLIED, "llm:groq")
    assert result.files[0].patched == 'resource "aws_instance" "web" {\n}\n'


def test_llm_edits_that_cannot_be_verified_become_suggestions(tmp_path):
    text = (
        'resource "aws_security_group" "web" {\n'
        '  name    = "web"\n'
        '  ingress = [{ from_port = 443, to_port = 443, protocol = "tcp", cidr_blocks = ["0.0.0.0/0"] }]\n'
        "}\n"
    )
    (tmp_path / "main.tf").write_text(text)
    https = sg_rule("HTTPS", 443)
    item = drift_item(
        "aws_security_group.web",
        security_group([https]),
        security_group([{**https, "from_port": 8443, "to_port": 8443}]),
    )
    suggested = text.replace("443, to_port = 443", "8443, to_port = 8443").rstrip("\n")
    api = FakeAPI(chat(f"```hcl\n{suggested}\n```"), chat(REVIEW))
    result = patcher_for("groq", api).patch(DriftReport(items=[item]), tmp_path)

    assert result.files == [], "unverified edits are never committed"
    assert {o.status for o in result.outcomes} == {SKIPPED}
    [(address, diff)] = result.suggestions
    assert address == "aws_security_group.web" and "+  ingress = [{ from_port = 8443" in diff


def test_api_errors_never_break_the_run(example_plan, example_workdir):
    api = FakeAPI(httpx.Response(401, json={"error": {"message": "Invalid API Key"}}))
    result = patcher_for("groq", api).patch(detect_drift(example_plan), example_workdir)
    assert [o.status for o in result.outcomes] == [APPLIED, APPLIED]
    assert result.warnings == ["AI review unavailable: groq API HTTP 401: Invalid API Key"]
    assert len(api.requests) == 1, "4xx errors other than 408/409/429 are not retried"


def test_rate_limits_are_retried_with_retry_after(example_plan, example_workdir):
    limited = httpx.Response(429, headers={"retry-after": "2"}, json={"error": {"message": "slow down"}})
    sleeps: list[float] = []
    api = FakeAPI(limited, chat(REVIEW))
    result = patcher_for("groq", api, sleeps).patch(detect_drift(example_plan), example_workdir)
    assert sleeps == [2.0] and len(api.requests) == 2 and result.ai_notes


def test_retries_give_up_with_exponential_backoff(example_plan, example_workdir):
    sleeps: list[float] = []
    api = FakeAPI(httpx.Response(503, text="upstream unavailable"))
    result = patcher_for("gemini", api, sleeps).patch(detect_drift(example_plan), example_workdir)
    assert sleeps == [1.0, 2.0, 4.0] and len(api.requests) == 4
    assert "after 4 attempts" in result.warnings[0]


def test_network_errors_are_retried(example_plan, example_workdir):
    def boom(request):
        raise httpx.ConnectError("connection refused", request=request)

    sleeps: list[float] = []
    api = FakeAPI(boom, boom, chat(REVIEW))
    result = patcher_for("groq", api, sleeps).patch(detect_drift(example_plan), example_workdir)
    assert sleeps == [1.0, 2.0] and result.ai_notes


# --------------------------------------------------------------------------- Anthropic


def test_anthropic_request_shape(example_plan, example_workdir):
    api = FakeAPI(claude(REVIEW))
    result = patcher_for("anthropic", api).patch(detect_drift(example_plan), example_workdir)
    [request] = api.requests
    assert str(request.url) == "https://api.anthropic.com/v1/messages"
    assert request.headers["x-api-key"] == "test-key"
    assert request.headers["anthropic-version"] == "2026-10-21"
    assert request.headers["anthropic-beta"] == "server-side-fallback-2026-07-01"
    body = api.bodies[0]
    assert body["model"] == "claude-opus-5-5"
    assert body["fallbacks"] == "default"
    assert body["output_config"] == {"effort": "medium"}
    assert body["max_tokens"] == 16000
    assert body["system"] == REVIEW_SYSTEM
    assert "temperature" not in body
    assert len(result.ai_notes) == 2  # text blocks only; the (empty) thinking block is ignored


def test_anthropic_optional_features_can_be_switched_off(example_plan, example_workdir):
    api = FakeAPI(claude(REVIEW))
    env = {"ANTHROPIC_EFFORT": "off", "ANTHROPIC_FALLBACKS": "", "LLM_MODEL": "claude-sonnet-5-5"}
    patcher_for("anthropic", api, **env).patch(detect_drift(example_plan), example_workdir)
    body = api.bodies[0]
    assert "output_config" not in body and "fallbacks" not in body
    assert "anthropic-beta" not in api.requests[0].headers
    assert body["model"] == "claude-sonnet-5-5"


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (
            claude("", stop="refusal", stop_details={"type": "refusal", "category": "cyber"}),
            "declined the request (cyber)",
        ),
        (claude("- partial", stop="max_tokens"), "truncated"),
        (httpx.Response(200, json={"content": [], "stop_reason": "end_turn"}), "no text"),
    ],
)
def test_anthropic_unusable_responses_become_warnings(response, message, example_plan, example_workdir):
    result = patcher_for("anthropic", FakeAPI(response)).patch(detect_drift(example_plan), example_workdir)
    assert [o.status for o in result.outcomes] == [APPLIED, APPLIED]
    assert any(message in w for w in result.warnings), result.warnings


def test_anthropic_always_mode_patch(example_plan, example_workdir):
    api = FakeAPI(claude(f"```hcl\n{example_block(FIXED)}\n```\nNOTES:\n- none"), claude(REVIEW))
    result = patcher_for("anthropic", api, LLM_PATCH_MODE="always").patch(detect_drift(example_plan), example_workdir)
    assert [o.engine for o in result.outcomes] == ["llm:anthropic", "llm:anthropic"]


# --------------------------------------------------------------------------- prompts and output hygiene


def test_patch_prompt_locates_nested_blocks(example_plan):
    item = detect_drift(example_plan).actionable_items[0]
    prompt = build_patch_prompt(item, example_block(), item.actionable_changes)
    assert (
        '- `ingress[0].from_port`: 443 -> 8443 (inside the `ingress` block where description="HTTPS from the internet"'
        in prompt
    )


def test_sanitize_note():
    assert sanitize_note("ping @octocat <script>x</script>") == "ping @​octocat &lt;script&gt;x&lt;/script&gt;"
    assert len(sanitize_note("x" * 1000)) == 400
