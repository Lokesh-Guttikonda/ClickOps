"""Update ``.tf`` files so the code matches live infrastructure (the "AI analyzer").

Modes, selected with the ``PROVIDER`` environment variable (or ``--provider``):

``mock`` (default)
    Deterministic, offline rules engine. Edits HCL surgically -- only the drifted values
    change -- and never talks to the network.
``groq`` / ``gemini``
    The rules engine runs first; a free-tier LLM reached through its OpenAI-compatible
    REST endpoint (plain ``httpx``, no SDK) patches whatever the rules could not, and
    writes reviewer notes. Set ``LLM_PATCH_MODE=always`` to have the LLM patch every
    resource (its output is still validated against the rules engine).
``anthropic``
    Same as above through the Claude Messages API.

LLM output is never trusted blindly: it must parse, keep the resource header, leave
untouched attributes byte-for-byte equal, and actually set every drifted value. If any
check fails the deterministic result is used and a warning is recorded. Only the affected
resource block and non-sensitive values are sent; CloudTrail identities never leave the
runner.
"""

from __future__ import annotations

import copy
import dataclasses
import difflib
import json
import logging
import os
import re
import shutil
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NamedTuple, Protocol

from . import __version__, hcl
from .detector import AttributeChange, DriftItem, DriftReport, format_path, get_path, values_equal

log = logging.getLogger(__name__)

APPLIED = "applied"
IN_SYNC = "in_sync"
SKIPPED = "skipped"

SUPPORTED_PROVIDERS = ("mock", "groq", "gemini", "anthropic")
PATCH_MODES = ("fallback", "always")


class ConfigError(RuntimeError):
    """The patcher is misconfigured (unknown provider, missing API key, ...)."""


class LLMError(RuntimeError):
    """An LLM call failed or returned something unusable."""


# --------------------------------------------------------------------------- results


@dataclass
class PatchOutcome:
    address: str
    change: AttributeChange | None  # None = whole resource (e.g. deleted)
    status: str  # applied | in_sync | skipped
    reason: str = ""
    engine: str = "rules"
    file: Path | None = None
    llm_eligible: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "path": self.change.dotted if self.change else None,
            "status": self.status,
            "reason": self.reason,
            "engine": self.engine,
            "file": str(self.file) if self.file else None,
        }


@dataclass
class FilePatch:
    path: Path
    original: str
    patched: str
    crlf: bool = False

    def diff(self, label: str | None = None) -> str:
        label = label or self.path.name
        lines = difflib.unified_diff(
            self.original.splitlines(keepends=True),
            self.patched.splitlines(keepends=True),
            fromfile=f"a/{label}",
            tofile=f"b/{label}",
        )
        return "".join(line if line.endswith("\n") else line + "\n" for line in lines)

    def stats(self) -> tuple[int, int]:
        added = removed = 0
        for line in self.diff().splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                added += 1
            elif line.startswith("-") and not line.startswith("---"):
                removed += 1
        return added, removed


@dataclass
class PatchResult:
    provider: str
    engine: str
    files: list[FilePatch] = field(default_factory=list)
    outcomes: list[PatchOutcome] = field(default_factory=list)
    ai_notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    #: LLM edits that passed the safety checks but could not be verified mechanically.
    #: They are shown to reviewers as (address, unified diff) and never committed.
    suggestions: list[tuple[str, str]] = field(default_factory=list)

    @property
    def applied(self) -> list[PatchOutcome]:
        return [o for o in self.outcomes if o.status == APPLIED]

    @property
    def skipped(self) -> list[PatchOutcome]:
        return [o for o in self.outcomes if o.status == SKIPPED]

    @property
    def changed(self) -> bool:
        return bool(self.files)

    def write(
        self, output_dir: str | os.PathLike[str] | None = None, root: str | os.PathLike[str] | None = None
    ) -> list[Path]:
        """Write patched files in place, or mirror them under ``output_dir``."""
        written = []
        for fp in self.files:
            if output_dir is None:
                dest = fp.path
            else:
                base = Path(root).resolve() if root else fp.path.parent
                try:
                    rel = fp.path.resolve().relative_to(base)
                except ValueError:
                    rel = Path(fp.path.name)
                dest = Path(output_dir) / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            data = fp.patched.replace("\n", "\r\n") if fp.crlf else fp.patched
            dest.write_text(data, encoding="utf-8", newline="")
            written.append(dest)
        return written

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "engine": self.engine,
            "files": [str(f.path) for f in self.files],
            "outcomes": [o.to_dict() for o in self.outcomes],
            "ai_notes": self.ai_notes,
            "suggestions": [{"address": a, "diff": d} for a, d in self.suggestions],
            "warnings": self.warnings,
        }


# --------------------------------------------------------------------------- rules engine


class _Step(NamedTuple):
    text: str
    status: str
    reason: str = ""
    llm_eligible: bool = False


def _skip(text: str, reason: str, *, eligible: bool = False) -> _Step:
    return _Step(text, SKIPPED, reason, eligible)


def _applied(text: str) -> _Step:
    return _Step(text, APPLIED)


def _in_sync(text: str, reason: str = "code already matches the live value") -> _Step:
    return _Step(text, IN_SYNC, reason)


def _short(expr: str, limit: int = 48) -> str:
    expr = " ".join(expr.split())
    return expr if len(expr) <= limit else expr[: limit - 1] + "…"


def _is_empty(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _prune(element: Any) -> Any:
    """Drop unset values (null, "", [], {}) that providers echo back for every field."""
    if isinstance(element, dict):
        pruned = {k: _prune(v) for k, v in element.items() if not _is_empty(v)}
        ordered = {k: pruned[k] for k in ("description", "name") if k in pruned}
        ordered.update({k: v for k, v in pruned.items() if k not in ordered})
        return ordered
    if isinstance(element, list):
        return [_prune(v) for v in element]
    return element


def _replace(text: str, start: int, end: int, new: str) -> str:
    return text[:start] + new + text[end:]


def _line_start(text: str, offset: int) -> int:
    return text.rfind("\n", 0, offset) + 1


def _indent_of_line(text: str, offset: int) -> str:
    start = _line_start(text, offset)
    return re.match(r"[ \t]*", text[start:]).group(0)  # type: ignore[union-attr]


def _child_indent(text: str, body: hcl.Body) -> str:
    for attr in body.attributes:
        if attr.owns_line(text):
            return attr.indent(text)
    for block in body.blocks:
        if block.owns_lines(text):
            return block.indent(text)
    return _indent_of_line(text, body.end) + "  "


def _insert_at_end(text: str, body: hcl.Body, snippet_lines: str, *, blank_line: bool) -> str:
    """Insert already-indented lines just before the body's closing brace."""
    close = body.end
    brace_line = _line_start(text, close)
    if text[brace_line:close].strip() == "":
        lead = "\n" if blank_line and (body.attributes or body.blocks) else ""
        return text[:brace_line] + lead + snippet_lines + "\n" + text[brace_line:]
    # closing brace shares a line with other code, e.g. "{}"
    return text[:close] + "\n" + snippet_lines + "\n" + _indent_of_line(text, close) + text[close:]


def _insert_attribute(text: str, body: hcl.Body, name: str, value: Any) -> _Step:
    key = hcl.render_key(name)
    anchors = [a for a in body.attributes if a.owns_line(text)]
    if anchors:
        anchor = anchors[-1]
        indent = anchor.indent(text)
        eq = text.find("=", anchor.key_start, anchor.value_start)
        width = (eq - anchor.key_start - 1) if eq != -1 else len(key)
        line = f"{indent}{key.ljust(max(width, len(key)))} = {hcl.render_value(value, indent)}\n"
        pos = anchor.line_end
        if text[pos - 1 : pos] != "\n":
            line = "\n" + line
        return _applied(text[:pos] + line + text[pos:])
    if body.blocks and body.blocks[0].owns_lines(text):
        first = body.blocks[0]
        indent = first.indent(text)
        line = f"{indent}{key} = {hcl.render_value(value, indent)}\n\n"
        return _applied(text[: first.line_start] + line + text[first.line_start :])
    indent = _child_indent(text, body)
    return _applied(_insert_at_end(text, body, f"{indent}{key} = {hcl.render_value(value, indent)}", blank_line=False))


def _delete_lines(text: str, start: int, end: int) -> str:
    """Delete whole lines [start, end) and tidy the blank lines around the gap."""

    def line_at(offset: int) -> str:
        nl = text.find("\n", offset)
        return text[offset : len(text) if nl == -1 else nl]

    # take comment lines directly above with us
    while start > 0:
        prev_start = _line_start(text, start - 1)
        if text[prev_start : start - 1].strip().startswith(("#", "//")):
            start = prev_start
        else:
            break
    prev_line = text[_line_start(text, start - 1) : start - 1] if start > 0 else None
    next_line = line_at(end) if end < len(text) else None
    prev_blank = prev_line is not None and prev_line.strip() == ""
    next_blank = next_line is not None and next_line.strip() == ""
    if next_blank and (prev_blank or (prev_line or "").rstrip().endswith("{")):
        end += len(next_line or "") + 1
    elif prev_blank and next_line is not None and next_line.strip().startswith("}"):
        start = _line_start(text, start - 1)
    return text[:start] + text[min(end, len(text)) :]


def _delete_attribute(text: str, attr: hcl.Attribute) -> _Step:
    if not attr.owns_line(text):
        return _skip(text, f"`{attr.name}` shares a line with other code", eligible=True)
    return _applied(_delete_lines(text, attr.line_start, attr.line_end))


def _delete_block(text: str, block: hcl.Block) -> _Step:
    if not block.owns_lines(text):
        return _skip(text, f"`{block.type}` block shares a line with other code", eligible=True)
    return _applied(_delete_lines(text, block.line_start, block.line_end))


def _insert_block(text: str, body: hcl.Body, block_type: str, element: Any, after: hcl.Block | None) -> _Step:
    if not isinstance(element, dict):
        return _skip(text, f"cannot render new `{block_type}` block", eligible=True)
    element = _prune(element)
    if after is not None and after.owns_lines(text):
        indent = after.indent(text)
        pos = after.line_end
        lead = "" if text[pos - 1 : pos] == "\n" else "\n"
        snippet = lead + "\n" + hcl.render_block(block_type, element, indent) + "\n"
        return _applied(text[:pos] + snippet + text[pos:])
    indent = _child_indent(text, body)
    return _applied(_insert_at_end(text, body, hcl.render_block(block_type, element, indent), blank_line=True))


_ANY = object()


def _candidates(item: DriftItem, list_path: tuple, element: dict) -> dict[str, list[Any]]:
    """Acceptable values for each attribute of a nested block: old state or live value.

    Accepting both lets matching work before, during and after patching (idempotency).
    """
    cands: dict[str, list[Any]] = {k: [v] for k, v in element.items()}
    depth = len(list_path)
    for change in item.changes:
        if change.path[:depth] != list_path or len(change.path) <= depth:
            continue
        key = change.path[depth]
        if not isinstance(key, str):
            continue
        if len(change.path) == depth + 1:
            cands.setdefault(key, []).append(change.after)
        else:
            cands.setdefault(key, []).append(_ANY)
    return cands


def _score_block(text: str, block: hcl.Block, cands: Mapping[str, list[Any]]) -> int:
    score = 0
    for attr in block.body.attributes:
        options = cands.get(attr.name)
        if options is None or _ANY in options:
            continue
        try:
            value = hcl.parse_literal(attr.value(text))
        except hcl.NotLiteral:
            continue
        if any(values_equal(value, option) for option in options):
            score += 1
        else:
            return -1
    return score


def _match_block(text: str, blocks: Sequence[hcl.Block], cands: Mapping[str, list[Any]]) -> hcl.Block | None:
    best: hcl.Block | None = None
    best_score, tie = 0, False
    for block in blocks:
        score = _score_block(text, block, cands)
        if score > best_score:
            best, best_score, tie = block, score, False
        elif score == best_score and score > 0:
            tie = True
    return None if tie else best


def _set_nested(obj: dict, path: Sequence[Any], value: Any) -> bool:
    node = obj
    for part in path[:-1]:
        if not isinstance(part, str) or not isinstance(node, dict):
            return False
        node = node.setdefault(part, {})
    last = path[-1]
    if not isinstance(last, str) or not isinstance(node, dict):
        return False
    if value is None:
        node.pop(last, None)
    else:
        node[last] = copy.deepcopy(value)
    return True


def _nest(path: Sequence[Any], value: Any) -> Any:
    for part in reversed(path):
        value = {part: value}
    return value


def _set_attribute(text: str, body: hcl.Body, name: str, change: AttributeChange) -> _Step:
    attr = body.attribute(name)
    if attr is None:
        if _is_empty(change.after):
            return _in_sync(text, "attribute is already absent from the code")
        return _insert_attribute(text, body, name, change.after)
    value_text = attr.value(text)
    try:
        current = hcl.parse_literal(value_text)
    except hcl.NotLiteral:
        return _skip(
            text,
            f"`{name}` is set by an expression (`{_short(value_text)}`); update its source "
            "(variable, local or module input) by hand",
        )
    if values_equal(current, change.after):
        return _in_sync(text)
    if change.after is None:
        return _delete_attribute(text, attr)
    indent = attr.indent(text) or _indent_of_line(text, attr.key_start)
    return _applied(_replace(text, attr.value_start, attr.value_end, hcl.render_value(change.after, indent)))


def _apply_nested_blocks(
    text: str, body: hcl.Body, item: DriftItem, change: AttributeChange, k: int, before_obj: Any, prefix: tuple
) -> _Step:
    path = change.path
    block_type, index = path[k], path[k + 1]
    whole_element = len(path) == k + 2
    blocks = body.blocks_of(block_type)
    list_path = prefix + (block_type, index)

    if not blocks:
        if any(b.type == "dynamic" and b.labels[:1] == [block_type] for b in body.blocks):
            return _skip(text, f"`{block_type}` blocks come from a `dynamic` block; update its for_each input by hand")
        if body.attribute(block_type) is not None:
            return _skip(text, f"`{block_type}` is set as a list attribute rather than nested blocks", eligible=True)
        if whole_element and change.kind == "added":
            return _insert_block(text, body, block_type, change.after, after=None)
        if whole_element and change.kind == "removed":
            return _in_sync(text, f"`{block_type}` block is already absent from the code")
        return _skip(text, f"no `{block_type}` block found in the code", eligible=True)

    if whole_element and change.kind == "added":
        if isinstance(change.after, dict) and _match_block(text, blocks, {k2: [v] for k2, v in change.after.items()}):
            return _in_sync(text, f"`{block_type}` block already present in the code")
        return _insert_block(text, body, block_type, change.after, after=blocks[-1])

    elements = get_path(before_obj, (block_type,))
    element = elements[index] if isinstance(elements, list) and index < len(elements) else None
    if not isinstance(element, dict):
        return _skip(text, f"state has no `{format_path(list_path)}` element", eligible=True)
    target = _match_block(text, blocks, _candidates(item, list_path, element))
    if target is None:
        if whole_element and change.kind == "removed":
            return _in_sync(text, f"`{block_type}` block is already absent from the code")
        return _skip(
            text, f"could not tell which `{block_type}` block in the code is `{format_path(list_path)}`", eligible=True
        )
    if whole_element:
        if change.kind == "removed":
            return _delete_block(text, target)
        return _skip(text, f"unsupported change to `{format_path(list_path)}`", eligible=True)
    return _apply_in_body(text, target.body, item, change, k + 2, element, list_path)


def _apply_in_body(
    text: str, body: hcl.Body, item: DriftItem, change: AttributeChange, k: int, before_obj: Any, prefix: tuple
) -> _Step:
    path = change.path
    name = path[k]
    if not isinstance(name, str):
        return _skip(text, f"unsupported path `{change.dotted}`", eligible=True)
    rest = path[k + 1 :]
    if not rest:
        return _set_attribute(text, body, name, change)
    if isinstance(rest[0], int):
        return _apply_nested_blocks(text, body, item, change, k, before_obj, prefix)

    attr = body.attribute(name)
    if attr is None:
        if any(not isinstance(p, str) for p in rest):
            return _skip(text, f"`{format_path(prefix + (name,))}` not found in the code", eligible=True)
        if _is_empty(change.after):
            return _in_sync(text, "attribute is already absent from the code")
        return _insert_attribute(text, body, name, _nest(rest, change.after))

    value_text = attr.value(text)
    if "\n" not in value_text:
        # single-line value: edit it as a whole literal (e.g. tags = { Name = "web" })
        try:
            current = hcl.parse_literal(value_text)
        except hcl.NotLiteral:
            return _skip(text, f"`{name}` is set by an expression (`{_short(value_text)}`); update its source by hand")
        if not isinstance(current, dict):
            return _skip(text, f"`{name}` is not a map in the code", eligible=True)
        if values_equal(get_path(current, rest), change.after):
            return _in_sync(text)
        updated = copy.deepcopy(current)
        if not _set_nested(updated, rest, change.after):
            return _skip(text, f"unsupported path `{change.dotted}`", eligible=True)
        indent = attr.indent(text) or _indent_of_line(text, attr.key_start)
        return _applied(_replace(text, attr.value_start, attr.value_end, hcl.render_value(updated, indent)))

    nested = hcl.object_body(text, attr)
    if nested is None:
        return _skip(text, f"`{name}` is set by an expression (`{_short(value_text)}`); update its source by hand")
    return _apply_in_body(text, nested, item, change, k + 1, get_path(before_obj, (name,)), prefix + (name,))


def apply_change(text: str, item: DriftItem, change: AttributeChange) -> _Step:
    """Apply one attribute change to the resource's block in ``text`` (deterministic)."""
    try:
        doc = hcl.parse(text)
    except hcl.HclError as exc:
        return _skip(text, f"could not parse the file: {exc}")
    block = hcl.find_resource(doc, item.type, item.name)
    if block is None:
        return _skip(text, f'resource "{item.type}" "{item.name}" not found in the file')
    return _apply_in_body(text, block.body, item, change, 0, item.before, ())


# --------------------------------------------------------------------------- locating code


def _is_local_source(source: str) -> bool:
    return source.startswith(("./", "../"))


class ResourceLocator:
    """Find the ``.tf`` file that declares a resource address."""

    def __init__(self, workdir: str | os.PathLike[str]) -> None:
        self.workdir = Path(workdir).resolve()
        self._manifest: dict[str, dict] | None = None

    def _load_manifest(self) -> dict[str, dict]:
        if self._manifest is None:
            self._manifest = {}
            path = self.workdir / ".terraform" / "modules" / "modules.json"
            if path.is_file():
                try:
                    for entry in json.loads(path.read_text(encoding="utf-8")).get("Modules", []):
                        self._manifest[entry.get("Key", "")] = entry
                except (json.JSONDecodeError, OSError) as exc:
                    log.warning("could not read %s: %s", path, exc)
        return self._manifest

    def module_dir(self, module_address: str | None) -> tuple[Path | None, str]:
        if not module_address:
            return self.workdir, ""
        names = re.findall(r"module\.([A-Za-z0-9_-]+)", module_address)
        key = ".".join(names)
        manifest = self._load_manifest()
        if key in manifest:
            entry = manifest[key]
            source = entry.get("Source", "")
            if not _is_local_source(source):
                return None, f"`{module_address}` comes from `{source}`; change its inputs instead"
            return (self.workdir / entry.get("Dir", source)).resolve(), ""
        current = self.workdir
        for name in names:
            source = None
            for tf in sorted(current.glob("*.tf")):
                try:
                    doc = hcl.parse(tf.read_text(encoding="utf-8"))
                except (hcl.HclError, OSError):
                    continue
                for block in doc.blocks:
                    if block.type == "module" and block.labels == [name]:
                        attr = block.body.attribute("source")
                        if attr is not None:
                            try:
                                source = hcl.parse_literal(attr.value(tf.read_text(encoding="utf-8")))
                            except hcl.NotLiteral:
                                source = None
            if not isinstance(source, str):
                return None, f"could not find the source of module `{name}`"
            if not _is_local_source(source):
                return None, f"`{module_address}` comes from `{source}`; change its inputs instead"
            current = (current / source).resolve()
        return current, ""

    def find(self, item: DriftItem) -> tuple[Path | None, str]:
        directory, reason = self.module_dir(item.module_address)
        if directory is None:
            return None, reason
        header = re.compile(rf'resource\s+"{re.escape(item.type)}"\s+"{re.escape(item.name)}"')
        for tf in sorted(directory.glob("*.tf")):
            try:
                text = tf.read_text(encoding="utf-8")
            except OSError:
                continue
            if not header.search(text):
                continue
            try:
                if hcl.find_resource(hcl.parse(text), item.type, item.name):
                    return tf, ""
            except hcl.HclError as exc:
                return None, f"found the resource in {tf.name} but could not parse it: {exc}"
        return None, f'resource "{item.type}" "{item.name}" not found in {directory}/*.tf'


# --------------------------------------------------------------------------- LLM clients


class LLMClient(Protocol):
    provider: str
    model: str

    def complete(self, system: str, prompt: str) -> str: ...


RETRY_STATUSES = frozenset({408, 409, 429, 500, 502, 503, 504, 529})


def _error_message(response: Any) -> str:
    try:
        data = response.json()
    except ValueError:
        return (response.text or "").strip()[:300]
    if isinstance(data, list) and data:
        data = data[0]
    if isinstance(data, dict):
        err = data.get("error", data)
        if isinstance(err, dict):
            return str(err.get("message") or err)[:300]
        return str(err)[:300]
    return str(data)[:300]


class _HttpLLM:
    provider = "llm"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        timeout: float = 60,
        max_retries: int = 3,
        transport: Any = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - exercised only without httpx
            raise ConfigError(f"PROVIDER={self.provider} needs httpx: pip install httpx") from exc
        self._httpx = httpx
        self.api_key = api_key
        self.model = model
        self.max_retries = max_retries
        self._sleep = sleep
        self._client = httpx.Client(
            timeout=timeout, transport=transport, headers={"User-Agent": f"terradrift-ai/{__version__}"}
        )

    def _post(self, url: str, headers: dict[str, str], payload: dict[str, Any]) -> dict[str, Any]:
        last_error = "no attempt made"
        for attempt in range(self.max_retries + 1):
            try:
                response = self._client.post(url, headers=headers, json=payload)
            except self._httpx.TransportError as exc:
                last_error = f"network error: {exc}"
            else:
                if response.status_code < 400:
                    try:
                        return response.json()
                    except ValueError as exc:
                        raise LLMError(f"{self.provider} returned invalid JSON") from exc
                last_error = f"HTTP {response.status_code}: {_error_message(response)}"
                if response.status_code not in RETRY_STATUSES:
                    raise LLMError(f"{self.provider} API {last_error}")
                retry_after = response.headers.get("retry-after", "")
                if attempt < self.max_retries and retry_after.replace(".", "", 1).isdigit():
                    self._sleep(min(float(retry_after), 30.0))
                    continue
            if attempt < self.max_retries:
                self._sleep(min(2.0**attempt, 30.0))
        raise LLMError(f"{self.provider} API failed after {self.max_retries + 1} attempts ({last_error})")

    def close(self) -> None:
        self._client.close()


class OpenAICompatibleLLM(_HttpLLM):
    """Any ``/chat/completions`` endpoint: Groq, Gemini, OpenRouter, Ollama, vLLM, ..."""

    def __init__(self, provider: str, *, base_url: str, **kwargs: Any) -> None:
        self.provider = provider
        self.base_url = base_url.rstrip("/")
        super().__init__(**kwargs)

    def complete(self, system: str, prompt: str) -> str:
        data = self._post(
            f"{self.base_url}/chat/completions",
            {"Authorization": f"Bearer {self.api_key}"},
            {
                "model": self.model,
                "temperature": 0,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
            },
        )
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"unexpected {self.provider} response shape") from exc
        if not isinstance(content, str) or not content.strip():
            raise LLMError(f"{self.provider} returned an empty completion")
        return content


class AnthropicLLM(_HttpLLM):
    """Claude Messages API over plain HTTP."""

    provider = "anthropic"
    API_URL = "https://api.anthropic.com/v1/messages"
    API_VERSION = "2026-10-21"
    FALLBACK_BETA = "server-side-fallback-2026-07-01"

    def __init__(
        self,
        *,
        effort: str | None = "medium",
        fallbacks: str | None = "default",
        base_url: str | None = None,
        **kwargs: Any,
    ) -> None:
        self.effort = effort or None
        self.fallbacks = fallbacks or None
        self.url = (base_url.rstrip("/") + "/v1/messages") if base_url else self.API_URL
        super().__init__(**kwargs)

    def complete(self, system: str, prompt: str) -> str:
        headers = {"x-api-key": self.api_key, "anthropic-version": self.API_VERSION}
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": 16000,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
        if self.effort:
            payload["output_config"] = {"effort": self.effort}
        if self.fallbacks:
            # If a safety classifier declines, retry server-side on Anthropic's recommended model.
            payload["fallbacks"] = self.fallbacks
            headers["anthropic-beta"] = self.FALLBACK_BETA
        data = self._post(self.url, headers, payload)
        stop = data.get("stop_reason")
        if stop == "refusal":
            category = (data.get("stop_details") or {}).get("category")
            raise LLMError("Claude declined the request" + (f" ({category})" if category else ""))
        if stop == "max_tokens":
            raise LLMError("Claude's response was truncated (max_tokens)")
        text = "".join(
            block.get("text", "") for block in data.get("content") or [] if block.get("type") == "text"
        ).strip()
        if not text:
            raise LLMError("Claude returned no text")
        return text


OPENAI_COMPATIBLE: dict[str, dict[str, Any]] = {
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "key_env": ("GROQ_API_KEY",),
        "model": "llama-3.3-70b-versatile",
    },
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "key_env": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
        "model": "gemini-2.5-flash",
    },
}
ANTHROPIC_DEFAULT_MODEL = "claude-opus-5-5"


def _off(value: str | None) -> str | None:
    if value is None:
        return None
    return None if value.strip().lower() in ("", "off", "none", "false", "0") else value.strip()


def build_llm_client(
    provider: str, env: Mapping[str, str], *, transport: Any = None, sleep: Callable[[float], None] = time.sleep
) -> LLMClient:
    timeout = float(env.get("LLM_TIMEOUT") or (120 if provider == "anthropic" else 60))
    if provider in OPENAI_COMPATIBLE:
        spec = OPENAI_COMPATIBLE[provider]
        key = next((env[name] for name in spec["key_env"] if env.get(name)), None)
        if not key:
            raise ConfigError(f"PROVIDER={provider} needs {spec['key_env'][0]}")
        return OpenAICompatibleLLM(
            provider,
            base_url=env.get("LLM_BASE_URL") or spec["base_url"],
            api_key=key,
            model=env.get("LLM_MODEL") or spec["model"],
            timeout=timeout,
            transport=transport,
            sleep=sleep,
        )
    if provider == "anthropic":
        key = env.get("ANTHROPIC_API_KEY")
        if not key:
            raise ConfigError("PROVIDER=anthropic needs ANTHROPIC_API_KEY")
        return AnthropicLLM(
            api_key=key,
            model=env.get("LLM_MODEL") or ANTHROPIC_DEFAULT_MODEL,
            effort=_off(env.get("ANTHROPIC_EFFORT", "medium")),
            fallbacks=_off(env.get("ANTHROPIC_FALLBACKS", "default")),
            base_url=env.get("ANTHROPIC_BASE_URL"),
            timeout=timeout,
            transport=transport,
            sleep=sleep,
        )
    raise ConfigError(f"{provider!r} is not an LLM provider")


# --------------------------------------------------------------------------- prompts

PATCH_SYSTEM = """You are terradrift-ai, a careful Terraform engineer. Someone changed AWS \
infrastructure by hand ("ClickOps"). Edit ONE Terraform resource block so its configuration \
matches the live values you are given.

Rules:
- Apply only the requested changes. Keep every other line, comment, attribute and nested
  block exactly as it is.
- Write values as HCL literals: strings in double quotes, numbers and booleans bare,
  lists in [ ], maps as { key = value }.
- If a value comes from an expression (var., local., module. or data. references, resource
  references, function calls), do not replace it: leave it unchanged and say so in NOTES.
- To remove one element of a repeated nested block (such as one `ingress` block), delete
  that block. To add one, add a new nested block.
- Never add secrets, provider blocks, other resources, or explanations inside the code.

Reply in exactly this format:
```hcl
<the complete updated resource block>
```
NOTES:
- <one short bullet per change you could not apply, or "none">"""

REVIEW_SYSTEM = """You are a cloud security reviewer. You are given Terraform drift caused by manual \
changes in AWS ("ClickOps") together with deterministic risk findings. Reply with 2-5 short markdown \
bullet points for the pull-request reviewer: the likely intent of the change, its security or \
operational risk, and what to verify before merging. No headings, no preamble, and do not invent \
facts that are not in the input."""


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _locator(element: Any) -> str:
    if not isinstance(element, dict):
        return ""
    pruned = {k: v for k, v in _prune(element).items() if not isinstance(v, (dict, list)) or len(_json(v)) < 60}
    return ", ".join(f"{k}={_json(v)}" for k, v in pruned.items())


def build_patch_prompt(item: DriftItem, block_text: str, changes: Sequence[AttributeChange]) -> str:
    lines = [f"Resource: {item.address}", "", "Current Terraform code:", "```hcl", block_text, "```", ""]
    lines.append("Make the code match these live AWS values (code value -> live value):")
    for change in changes:
        list_path = next(
            (change.path[: i + 1] for i in range(len(change.path) - 1, -1, -1) if isinstance(change.path[i], int)),
            None,
        )
        if change.kind == "added" and list_path == change.path:
            lines.append(f"- add a new `{change.path[-2]}` block with: {_locator(change.after)}")
            continue
        where = ""
        if list_path is not None:
            element = get_path(item.before, list_path)
            where = f" (inside the `{list_path[-2]}` block where {_locator(element)})"
        if change.kind == "removed" and list_path == change.path:
            lines.append(f"- delete the `{change.path[-2]}` block where {_locator(change.before)}")
            continue
        lines.append(f"- `{change.dotted}`: {_json(change.before)} -> {_json(change.after)}{where}")
    return "\n".join(lines)


def build_review_prompt(report: DriftReport) -> str:
    from .risk import assess_risk

    lines = ["Drifted resources (Terraform code value -> live AWS value):"]
    for item in report.actionable_items:
        lines.append(f"\n{item.address}{' (DELETED outside Terraform)' if item.deleted else ''}")
        for change in item.actionable_changes:
            if change.sensitive:
                lines.append(f"- {change.dotted}: (sensitive value changed)")
            else:
                lines.append(f"- {change.dotted}: {_json(change.before)} -> {_json(change.after)}")
    findings = assess_risk(report)
    if findings:
        lines.append("\nDeterministic risk findings:")
        lines += [f"- [{f.level}] {f.address}: {f.message}" for f in findings]
    return "\n".join(lines)


_FENCE = re.compile(r"```[ \t]*(?:hcl|terraform|tf)?[ \t]*\r?\n(.*?)```", re.DOTALL | re.IGNORECASE)


def _bullets(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped[:1] in ("-", "*", "•") and len(stripped) > 1:
            note = stripped[1:].strip()
            if note and note.lower().rstrip(".") not in ("none", "n/a"):
                out.append(note)
    return out


def sanitize_note(note: str, limit: int = 400) -> str:
    """LLM text goes into a PR body: neutralise @mentions and raw HTML, cap the length."""
    note = " ".join(note.split()).replace("<", "&lt;").replace(">", "&gt;").replace("@", "@\u200b")
    return note if len(note) <= limit else note[: limit - 1] + "…"


def parse_patch_reply(reply: str) -> tuple[str, list[str]]:
    match = _FENCE.search(reply)
    if not match:
        raise LLMError("reply did not contain a ```hcl code block")
    return match.group(1).strip("\n"), _bullets(reply[match.end() :])


def _norm(text: str) -> str:
    return " ".join(text.split())


def _check_untouched(base: str, old: hcl.Block, candidate: str, new: hcl.Block, touched: set[str]) -> None:
    for attr in old.body.attributes:
        if attr.name in touched:
            continue
        twin = new.body.attribute(attr.name)
        if twin is None or _norm(twin.value(candidate)) != _norm(attr.value(base)):
            raise LLMError(f"modified `{attr.name}`, which was not part of the drift")
    for attr in new.body.attributes:
        if attr.name not in touched and old.body.attribute(attr.name) is None:
            raise LLMError(f"added `{attr.name}`, which was not part of the drift")
    for block_type in {b.type for b in old.body.blocks} | {b.type for b in new.body.blocks}:
        if block_type in touched:
            continue
        before = [_norm(base[b.start : b.close_brace + 1]) for b in old.body.blocks_of(block_type)]
        after = [_norm(candidate[b.start : b.close_brace + 1]) for b in new.body.blocks_of(block_type)]
        if before != after:
            raise LLMError(f"modified `{block_type}` blocks, which were not part of the drift")


# --------------------------------------------------------------------------- the patcher


class HclPatcher:
    def __init__(
        self,
        provider: str = "mock",
        llm: LLMClient | None = None,
        *,
        patch_mode: str = "fallback",
        fmt: str = "auto",
        terraform_bin: str = "terraform",
        warnings: Sequence[str] = (),
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    ) -> None:
        if patch_mode not in PATCH_MODES:
            raise ConfigError(f"LLM_PATCH_MODE must be one of {', '.join(PATCH_MODES)}")
        self.provider = provider
        self.llm = llm
        self.patch_mode = patch_mode
        self.fmt = fmt
        self.terraform_bin = terraform_bin
        self._init_warnings = list(warnings)
        self._runner = runner

    @property
    def engine(self) -> str:
        if self.llm is None:
            if self.provider == "mock":
                return "rules (deterministic, offline)"
            return f"rules (deterministic) - {self.provider} unavailable"
        return f"rules + {self.provider} `{self.llm.model}` (LLM patch mode: {self.patch_mode})"

    # -- public -------------------------------------------------------------

    def patch(self, report: DriftReport, workdir: str | os.PathLike[str]) -> PatchResult:
        locator = ResourceLocator(workdir)
        self._texts: dict[Path, str] = {}
        self._originals: dict[Path, str] = {}
        self._crlf: dict[Path, bool] = {}
        result = PatchResult(provider=self.provider, engine=self.engine, warnings=list(self._init_warnings))
        for item in report.actionable_items:
            result.outcomes += self._patch_item(item, locator, result)

        for path, original in self._originals.items():
            patched = self._texts[path]
            if patched == original:
                continue
            patched, problem = self._format(original, patched)
            if problem:
                result.warnings.append(f"{path.name}: {problem}; the patch for this file was discarded")
                for outcome in result.outcomes:
                    if outcome.file == path and outcome.status == APPLIED:
                        outcome.status, outcome.reason = SKIPPED, "patched file failed `terraform fmt` validation"
                continue
            result.files.append(FilePatch(path, original, patched, self._crlf[path]))

        if self.llm is not None and report.actionable_items:
            try:
                reply = self.llm.complete(REVIEW_SYSTEM, build_review_prompt(report))
                notes = _bullets(reply) or [reply.strip()]
                result.ai_notes += [sanitize_note(n) for n in notes[:6]]
            except LLMError as exc:
                result.warnings.append(f"AI review unavailable: {exc}")
        return result

    # -- internals ----------------------------------------------------------

    def _load(self, path: Path) -> str:
        if path not in self._texts:
            raw = path.read_bytes().decode("utf-8")
            self._crlf[path] = "\r\n" in raw
            text = raw.replace("\r\n", "\n")
            self._texts[path] = self._originals[path] = text
        return self._texts[path]

    def _patch_item(self, item: DriftItem, locator: ResourceLocator, result: PatchResult) -> list[PatchOutcome]:
        if item.deleted:
            return [
                PatchOutcome(
                    item.address,
                    None,
                    SKIPPED,
                    "deleted outside Terraform: run `terraform apply` to restore it, or remove the block if "
                    "the deletion was intended",
                )
            ]
        changes = item.actionable_changes
        if item.index is not None:
            reason = (
                f"`{item.address}` is one instance of a count/for_each resource; codifying it would "
                "change every instance"
            )
            return [PatchOutcome(item.address, c, SKIPPED, reason) for c in changes]
        path, reason = locator.find(item)
        if path is None:
            return [PatchOutcome(item.address, c, SKIPPED, reason) for c in changes]

        text_before = text = self._load(path)
        outcomes = []
        for change in changes:
            if change.sensitive:
                outcomes.append(
                    PatchOutcome(item.address, change, SKIPPED, "sensitive value: never written to code", file=path)
                )
                continue
            step = apply_change(text, item, change)
            text = step.text
            outcomes.append(
                PatchOutcome(item.address, change, step.status, step.reason, "rules", path, step.llm_eligible)
            )

        if self.llm is not None:
            wanted = self.patch_mode == "always" or any(o.status == SKIPPED and o.llm_eligible for o in outcomes)
            if wanted:
                try:
                    text, outcomes, notes, suggestion = self._llm_patch(item, text_before, text, outcomes)
                    result.ai_notes += [sanitize_note(f"`{item.address}`: {n}") for n in notes[:3]]
                    if suggestion:
                        result.suggestions.append((item.address, suggestion))
                except LLMError as exc:
                    result.warnings.append(
                        f"{self.provider} could not patch `{item.address}` ({exc}); kept the deterministic result"
                    )
        self._texts[path] = text
        return outcomes

    def _llm_patch(
        self, item: DriftItem, text_before: str, text_rules: str, outcomes: list[PatchOutcome]
    ) -> tuple[str, list[PatchOutcome], list[str], str | None]:
        """Ask the LLM to patch the block; adopt its edit only if every target verifies."""
        assert self.llm is not None
        always = self.patch_mode == "always"
        base = text_before if always else text_rules
        patchable = [o for o in outcomes if o.change is not None and not o.change.sensitive]
        targets = [o.change for o in patchable if always or (o.status == SKIPPED and o.llm_eligible)]
        if not targets:
            return text_rules, outcomes, [], None
        block = hcl.find_resource(hcl.parse(base), item.type, item.name)
        if block is None:
            raise LLMError("resource block disappeared")
        block_text = base[block.start : block.close_brace + 1]
        reply = self.llm.complete(PATCH_SYSTEM, build_patch_prompt(item, block_text, targets))
        new_block_text, notes = parse_patch_reply(reply)

        try:
            parsed = hcl.parse(new_block_text)
        except hcl.HclError as exc:
            raise LLMError(f"returned HCL does not parse ({exc})") from exc
        if parsed.attributes or len(parsed.blocks) != 1 or parsed.blocks[0].labels != [item.type, item.name]:
            raise LLMError(f'expected exactly one `resource "{item.type}" "{item.name}"` block')
        candidate = base[: block.start] + new_block_text.strip() + base[block.close_brace + 1 :]
        new_block = hcl.find_resource(hcl.parse(candidate), item.type, item.name)
        assert new_block is not None
        touched = {str(c.path[0]) for c in targets}
        _check_untouched(base, block, candidate, new_block, touched)

        label = f"llm:{self.provider}"
        updated = []
        for outcome in outcomes:
            change = outcome.change
            if change is None or change.sensitive:
                updated.append(outcome)
                continue
            verified = apply_change(candidate, item, change).status == IN_SYNC
            if outcome.status in (APPLIED, IN_SYNC):
                if not verified:
                    raise LLMError(f"output does not set `{change.dotted}` to the live value")
                engine = label if always and outcome.status == APPLIED else outcome.engine
                updated.append(dataclasses.replace(outcome, engine=engine))
            elif verified and outcome.llm_eligible:
                updated.append(
                    dataclasses.replace(outcome, status=APPLIED, reason="applied by the LLM (validated)", engine=label)
                )
            elif verified:
                raise LLMError(f"replaced the expression behind `{change.dotted}`")
            else:
                updated.append(outcome)
        if any(o.status == SKIPPED and o.llm_eligible for o in updated):
            # Some edits can't be checked mechanically: show them, don't commit them.
            diff = "".join(
                difflib.unified_diff(
                    block_text.splitlines(keepends=True),
                    (new_block_text.strip() + "\n").splitlines(keepends=True),
                    fromfile=f"a/{item.address}",
                    tofile=f"b/{item.address} (suggested)",
                )
            )
            return text_rules, outcomes, notes, diff or None
        return candidate, updated, notes, None

    def _format(self, original: str, patched: str) -> tuple[str, str | None]:
        """Validate with ``terraform fmt -`` when Terraform is installed.

        The formatted text is only adopted if the original file was already canonical,
        so we never reformat lines that have nothing to do with the drift.
        """
        if (self.fmt or "auto").lower() == "off":
            return patched, None
        executable = shutil.which(self.terraform_bin)
        if executable is None:
            return patched, None

        def fmt(text: str) -> subprocess.CompletedProcess:
            return self._runner(
                [executable, "fmt", "-no-color", "-"], input=text, capture_output=True, text=True, timeout=60
            )

        try:
            formatted = fmt(patched)
            if formatted.returncode != 0:
                return patched, f"`terraform fmt` rejected the patched file: {formatted.stderr.strip()[:300]}"
            canonical = fmt(original)
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.warning("terraform fmt unavailable: %s", exc)
            return patched, None
        if canonical.returncode == 0 and canonical.stdout == original:
            return formatted.stdout, None
        return patched, None


def get_patcher(
    provider: str | None = None,
    *,
    env: Mapping[str, str] | None = None,
    transport: Any = None,
    sleep: Callable[[float], None] = time.sleep,
) -> HclPatcher:
    """Build the patcher selected by ``provider`` or the ``PROVIDER`` env var."""
    env = os.environ if env is None else env
    name = (provider or env.get("PROVIDER") or "mock").strip().lower()
    if name not in SUPPORTED_PROVIDERS:
        raise ConfigError(f"unknown PROVIDER {name!r}; choose one of: {', '.join(SUPPORTED_PROVIDERS)}")
    fmt = env.get("TERRADRIFT_FMT", "auto")
    if name == "mock":
        return HclPatcher("mock", fmt=fmt)
    mode = (env.get("LLM_PATCH_MODE") or "fallback").strip().lower()
    try:
        llm = build_llm_client(name, env, transport=transport, sleep=sleep)
    except ConfigError as exc:
        log.warning("%s; using the deterministic patcher", exc)
        return HclPatcher(name, None, fmt=fmt, warnings=[f"{exc}; used the deterministic patcher instead"])
    return HclPatcher(name, llm, patch_mode=mode, fmt=fmt)
