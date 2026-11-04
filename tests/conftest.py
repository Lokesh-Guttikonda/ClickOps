"""Shared fixtures. Every test runs fully offline with no credentials in the environment."""

from __future__ import annotations

import json
import shutil
import socket
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"

_SCRUBBED_ENV = (
    "PROVIDER",
    "GROQ_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_EFFORT",
    "ANTHROPIC_FALLBACKS",
    "LLM_MODEL",
    "LLM_BASE_URL",
    "LLM_PATCH_MODE",
    "LLM_TIMEOUT",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITHUB_OUTPUT",
    "GITHUB_STEP_SUMMARY",
    "GITHUB_REPOSITORY",
    "GITHUB_API_URL",
    "TERRADRIFT_IGNORE_PRINCIPALS",
    "TERRADRIFT_BASE_BRANCH",
    "TERRADRIFT_LOOKBACK_HOURS",
    "AWS_PROFILE",
    "NO_COLOR",
)


@pytest.fixture(autouse=True)
def offline(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_network(*args, **kwargs):
        raise RuntimeError("network access is disabled in the test suite")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    for name in _SCRUBBED_ENV:
        monkeypatch.delenv(name, raising=False)
    # Don't let a locally installed terraform binary change patch results.
    monkeypatch.setenv("TERRADRIFT_FMT", "off")


@pytest.fixture
def example_plan() -> dict:
    return json.loads((EXAMPLES / "drifted_plan.json").read_text(encoding="utf-8"))


@pytest.fixture
def example_events() -> dict:
    return json.loads((EXAMPLES / "cloudtrail_events.json").read_text(encoding="utf-8"))


@pytest.fixture
def example_workdir(tmp_path: Path) -> Path:
    """A throwaway copy of examples/ so tests can patch main.tf freely."""
    work = tmp_path / "infra"
    shutil.copytree(EXAMPLES, work)
    return work
