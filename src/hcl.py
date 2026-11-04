"""A small, dependency-free HCL2 reader/writer built for surgical edits.

This is deliberately *not* a complete HCL implementation. It understands what the
patcher needs -- blocks, attributes, object literals, quoted strings (including
``${...}`` interpolation), heredocs and all three comment styles -- and it records
byte offsets for everything, so an edit can replace one value while leaving every
other character of the file (comments, alignment, blank lines) untouched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

__all__ = [
    "Attribute",
    "Block",
    "Body",
    "HclError",
    "NotLiteral",
    "find_resource",
    "line_number",
    "object_body",
    "parse",
    "parse_literal",
    "render_block",
    "render_key",
    "render_string",
    "render_value",
]


class HclError(ValueError):
    """The text is not HCL this parser can read."""


class NotLiteral(ValueError):
    """The expression is not a plain literal (e.g. ``var.port`` or ``merge(...)``)."""


_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_BARE_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
_HEREDOC = re.compile(r"<<(-?)([A-Za-z_][A-Za-z0-9_-]*)[ \t]*\r?\n")
_NUMBER = re.compile(r"-?\d+(\.\d+)?([eE][+-]?\d+)?")
_OPENERS = {"{": "}", "[": "]", "(": ")"}
_CLOSERS = frozenset(")]}")


def line_number(text: str, offset: int) -> int:
    """1-based line number of ``offset`` in ``text``."""
    return text.count("\n", 0, offset) + 1


# --------------------------------------------------------------------------- scanning


def _skip_line_comment(text: str, i: int) -> int:
    end = text.find("\n", i)
    return len(text) if end == -1 else end


def _skip_block_comment(text: str, i: int) -> int:
    end = text.find("*/", i + 2)
    if end == -1:
        raise HclError(f"unterminated /* comment */ starting on line {line_number(text, i)}")
    return end + 2


def _skip_heredoc(text: str, match: re.Match[str]) -> int:
    marker = match.group(2)
    pos = match.end()
    while pos <= len(text):
        nl = text.find("\n", pos)
        line_end = len(text) if nl == -1 else nl
        if text[pos:line_end].strip() == marker:
            return line_end
        if nl == -1:
            break
        pos = nl + 1
    raise HclError(f"unterminated heredoc <<{marker} on line {line_number(text, match.start())}")


def skip_string(text: str, i: int) -> int:
    """``text[i]`` is ``"``; return the offset just past the closing quote."""
    n = len(text)
    i += 1
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return i + 1
        if c == "\n":
            break
        if text.startswith("$${", i) or text.startswith("%%{", i):
            i += 3  # escaped literal "${" / "%{"
            continue
        if text.startswith("${", i) or text.startswith("%{", i):
            i = skip_balanced(text, i + 1)
            continue
        i += 1
    raise HclError(f"unterminated string on line {line_number(text, i)}")


def skip_balanced(text: str, i: int) -> int:
    """``text[i]`` is an opening bracket; return the offset just past its partner."""
    n = len(text)
    stack = [_OPENERS[text[i]]]
    i += 1
    while i < n:
        c = text[i]
        if c == '"':
            i = skip_string(text, i)
            continue
        if c == "#" or text.startswith("//", i):
            i = _skip_line_comment(text, i)
            continue
        if text.startswith("/*", i):
            i = _skip_block_comment(text, i)
            continue
        if text.startswith("<<", i):
            heredoc = _HEREDOC.match(text, i)
            if heredoc:
                i = _skip_heredoc(text, heredoc)
                continue
        if c in _OPENERS:
            stack.append(_OPENERS[c])
        elif c in _CLOSERS:
            if c != stack[-1]:
                raise HclError(f"unexpected {c!r} on line {line_number(text, i)}")
            stack.pop()
            if not stack:
                return i + 1
        i += 1
    raise HclError("unbalanced brackets: reached end of file")


def _skip_inline_ws(text: str, i: int, end: int) -> int:
    while i < end and text[i] in " \t\r":
        i += 1
    return i


def _skip_trivia(text: str, i: int, end: int, *, commas: bool) -> int:
    """Skip whitespace, newlines, comments (and commas inside object literals)."""
    while i < end:
        c = text[i]
        if c.isspace() or (commas and c == ","):
            i += 1
        elif c == "#" or text.startswith("//", i):
            i = _skip_line_comment(text, i)
        elif text.startswith("/*", i):
            i = _skip_block_comment(text, i)
        else:
            break
    return i


def _scan_expression(text: str, i: int, end: int, *, object_mode: bool) -> int:
    """Return the exclusive end offset of the expression starting at ``i``.

    Outside brackets a newline ends an HCL expression; trailing whitespace and comments
    are not part of it. Inside object literals a comma also ends it.
    """
    last = i
    while i < end:
        c = text[i]
        if c == "\n" or c == "#" or text.startswith("//", i):
            break
        if object_mode and c == ",":
            break
        if c in _CLOSERS:
            break
        if text.startswith("/*", i):
            i = _skip_block_comment(text, i)
            continue
        if c == '"':
            i = last = skip_string(text, i)
            continue
        if text.startswith("<<", i):
            heredoc = _HEREDOC.match(text, i)
            if heredoc:
                i = last = _skip_heredoc(text, heredoc)
                continue
        if c in _OPENERS:
            i = last = skip_balanced(text, i)
            continue
        if not c.isspace():
            last = i + 1
        i += 1
    return last


def _line_start(text: str, offset: int) -> int:
    return text.rfind("\n", 0, offset) + 1


def _line_end(text: str, offset: int, end: int, *, object_mode: bool) -> int:
    """Offset just past the newline that ends the line containing ``offset``."""
    i = _skip_inline_ws(text, offset, end)
    if object_mode and i < end and text[i] == ",":
        i = _skip_inline_ws(text, i + 1, end)
    if i < end and (text[i] == "#" or text.startswith("//", i)):
        i = _skip_line_comment(text, i)
    if i < len(text) and text[i] == "\n":
        return i + 1
    return i


# --------------------------------------------------------------------------- tree


@dataclass
class Attribute:
    """``name = value``. Offsets index into the full document text."""

    name: str
    key_start: int
    value_start: int
    value_end: int
    line_start: int
    line_end: int

    def value(self, text: str) -> str:
        return text[self.value_start : self.value_end]

    def owns_line(self, text: str) -> bool:
        """True when nothing but indentation precedes the key on its line."""
        return text[self.line_start : self.key_start].strip() == ""

    def indent(self, text: str) -> str:
        return text[self.line_start : self.key_start] if self.owns_line(text) else ""


@dataclass
class Block:
    """``type "label" ... { body }``."""

    type: str
    labels: list[str]
    start: int
    open_brace: int
    close_brace: int
    line_start: int
    line_end: int
    body: Body

    def owns_lines(self, text: str) -> bool:
        return text[self.line_start : self.start].strip() == ""

    def indent(self, text: str) -> str:
        return text[self.line_start : self.start] if self.owns_lines(text) else ""


@dataclass
class Body:
    """Contents between ``{`` and ``}`` (or a whole file)."""

    start: int
    end: int
    attributes: list[Attribute]
    blocks: list[Block]

    def attribute(self, name: str) -> Attribute | None:
        for attr in self.attributes:
            if attr.name == name:
                return attr
        return None

    def blocks_of(self, block_type: str) -> list[Block]:
        return [b for b in self.blocks if b.type == block_type]


def _parse_body(text: str, start: int, end: int, *, object_mode: bool = False) -> Body:
    attributes: list[Attribute] = []
    blocks: list[Block] = []
    i = start
    while True:
        i = _skip_trivia(text, i, end, commas=object_mode)
        if i >= end:
            break
        key_start = i
        if text[i] == '"':
            j = skip_string(text, i)
            name = _decode_string(text[i + 1 : j - 1])
        else:
            m = _IDENT.match(text, i, end)
            if not m:
                raise HclError(f"unexpected {text[i]!r} on line {line_number(text, i)}")
            name, j = m.group(0), m.end()
        k = _skip_inline_ws(text, j, end)
        is_assign = k < end and ((text[k] == "=" and not text.startswith("==", k)) or (object_mode and text[k] == ":"))
        if is_assign:
            value_start = _skip_inline_ws(text, k + 1, end)
            value_end = _scan_expression(text, value_start, end, object_mode=object_mode)
            if value_end == value_start:
                raise HclError(f"missing value for {name!r} on line {line_number(text, key_start)}")
            attributes.append(
                Attribute(
                    name=name,
                    key_start=key_start,
                    value_start=value_start,
                    value_end=value_end,
                    line_start=_line_start(text, key_start),
                    line_end=_line_end(text, value_end, end, object_mode=object_mode),
                )
            )
            i = value_end
            continue
        if object_mode:
            raise HclError(f"expected '=' after {name!r} on line {line_number(text, key_start)}")
        labels: list[str] = []
        while True:
            k = _skip_inline_ws(text, k, end)
            if k >= end:
                raise HclError(f"block {name!r} has no body (line {line_number(text, key_start)})")
            if text[k] == "{":
                break
            if text[k] == '"':
                e = skip_string(text, k)
                labels.append(_decode_string(text[k + 1 : e - 1]))
                k = e
                continue
            m = _IDENT.match(text, k, end)
            if not m:
                raise HclError(f"unexpected {text[k]!r} on line {line_number(text, k)}")
            labels.append(m.group(0))
            k = m.end()
        close = skip_balanced(text, k) - 1
        if close >= end:
            raise HclError(f"block {name!r} is not closed (line {line_number(text, key_start)})")
        blocks.append(
            Block(
                type=name,
                labels=labels,
                start=key_start,
                open_brace=k,
                close_brace=close,
                line_start=_line_start(text, key_start),
                line_end=_line_end(text, close + 1, end, object_mode=False),
                body=_parse_body(text, k + 1, close),
            )
        )
        i = close + 1
    return Body(start=start, end=end, attributes=attributes, blocks=blocks)


def parse(text: str) -> Body:
    """Parse a whole ``.tf`` file."""
    return _parse_body(text, 0, len(text))


def find_resource(doc: Body, resource_type: str, name: str) -> Block | None:
    for block in doc.blocks:
        if block.type == "resource" and block.labels == [resource_type, name]:
            return block
    return None


def object_body(text: str, attr: Attribute) -> Body | None:
    """If ``attr``'s value is a ``{ ... }`` object literal, parse its contents."""
    if text[attr.value_start] != "{":
        return None
    try:
        if skip_balanced(text, attr.value_start) != attr.value_end:
            return None  # e.g. "{...} + something"
        return _parse_body(text, attr.value_start + 1, attr.value_end - 1, object_mode=True)
    except HclError:
        return None


# --------------------------------------------------------------------------- literals

_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}
_ESCAPE_RE = re.compile(r"\\(u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|.)|\$\$\{|%%\{", re.DOTALL)


def _decode_string(raw: str) -> str:
    def sub(m: re.Match[str]) -> str:
        token = m.group(0)
        if token == "$${":
            return "${"
        if token == "%%{":
            return "%{"
        esc = m.group(1)
        if esc[0] in "uU" and len(esc) > 1:
            return chr(int(esc[1:], 16))
        return _ESCAPES.get(esc, esc)

    return _ESCAPE_RE.sub(sub, raw)


def _has_template(raw: str) -> bool:
    stripped = raw.replace("$${", "").replace("%%{", "")
    return "${" in stripped or "%{" in stripped


class _LiteralParser:
    def __init__(self, src: str) -> None:
        self.s = src
        self.i = 0

    def parse(self) -> Any:
        value = self.value()
        self.ws()
        if self.i != len(self.s):
            raise NotLiteral(self.s)
        return value

    def ws(self) -> None:
        self.i = _skip_trivia(self.s, self.i, len(self.s), commas=False)

    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def value(self) -> Any:
        self.ws()
        c = self.peek()
        if c == '"':
            return self.string()
        if c == "[":
            return self.list()
        if c == "{":
            return self.object()
        number = _NUMBER.match(self.s, self.i)
        if number:
            self.i = number.end()
            token = number.group(0)
            return float(token) if (number.group(1) or number.group(2)) else int(token)
        ident = _IDENT.match(self.s, self.i)
        if ident:
            word = ident.group(0)
            self.i = ident.end()
            # "var.x", "aws_vpc.main.id", "file(...)" all start with an identifier
            if self.peek() in (".", "(", "["):
                raise NotLiteral(self.s)
            if word in ("true", "false"):
                return word == "true"
            if word == "null":
                return None
        raise NotLiteral(self.s)

    def string(self) -> str:
        try:
            end = skip_string(self.s, self.i)
        except HclError as exc:
            raise NotLiteral(self.s) from exc
        raw = self.s[self.i + 1 : end - 1]
        if _has_template(raw):
            raise NotLiteral(self.s)
        self.i = end
        return _decode_string(raw)

    def list(self) -> list[Any]:
        self.i += 1
        items: list[Any] = []
        while True:
            self.ws()
            if self.peek() == "]":
                self.i += 1
                return items
            items.append(self.value())
            self.ws()
            if self.peek() == ",":
                self.i += 1
            elif self.peek() != "]":
                raise NotLiteral(self.s)

    def object(self) -> dict[str, Any]:
        self.i += 1
        result: dict[str, Any] = {}
        while True:
            self.i = _skip_trivia(self.s, self.i, len(self.s), commas=True)
            if self.peek() == "}":
                self.i += 1
                return result
            if self.peek() == '"':
                key = self.string()
            else:
                ident = _IDENT.match(self.s, self.i)
                if not ident:
                    raise NotLiteral(self.s)
                key = ident.group(0)
                self.i = ident.end()
            self.ws()
            if self.peek() not in ("=", ":"):
                raise NotLiteral(self.s)
            self.i += 1
            result[key] = self.value()


def parse_literal(expression: str) -> Any:
    """Evaluate an HCL literal (string, number, bool, null, list, object).

    Raises :class:`NotLiteral` for anything that needs evaluation: references,
    function calls, interpolated templates, conditionals, for-expressions, heredocs.
    """
    return _LiteralParser(expression.strip()).parse()


# --------------------------------------------------------------------------- rendering


def render_string(value: str) -> str:
    out = []
    for ch in value:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out).replace("${", "$${").replace("%{", "%%{") + '"'


def render_key(key: str) -> str:
    return key if _BARE_KEY.match(key) else render_string(key)


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (bool, int, float, str))


def render_value(value: Any, indent: str = "", *, inline_limit: int = 80) -> str:
    """Render a JSON-like Python value as HCL. ``indent`` is the current line's indent."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() else repr(value)
    if isinstance(value, str):
        return render_string(value)
    inner = indent + "  "
    if isinstance(value, (list, tuple)):
        if not value:
            return "[]"
        items = [render_value(v, inner, inline_limit=inline_limit) for v in value]
        one_line = "[" + ", ".join(items) + "]"
        if all(_is_scalar(v) for v in value) and len(indent) + len(one_line) <= inline_limit:
            return one_line
        return "[\n" + "".join(f"{inner}{item},\n" for item in items) + indent + "]"
    if isinstance(value, dict):
        if not value:
            return "{}"
        keys = [render_key(str(k)) for k in value]
        width = max(len(k) for k in keys)
        lines = [
            f"{inner}{key.ljust(width)} = {render_value(v, inner, inline_limit=inline_limit)}"
            for key, v in zip(keys, value.values(), strict=True)
        ]
        return "{\n" + "\n".join(lines) + "\n" + indent + "}"
    raise TypeError(f"cannot render {type(value).__name__} as HCL")


def _is_block_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(v, dict) for v in value)


def render_block(block_type: str, body: dict[str, Any], indent: str = "", labels: tuple = ()) -> str:
    """Render a nested block such as ``ingress { ... }`` from a JSON object."""
    inner = indent + "  "
    attrs = [(k, v) for k, v in body.items() if not _is_block_list(v)]
    nested = [(k, v) for k, v in body.items() if _is_block_list(v)]
    header = block_type + "".join(f" {render_string(label)}" for label in labels) + " {"
    lines = [indent + header]
    width = max((len(render_key(k)) for k, _ in attrs), default=0)
    for key, value in attrs:
        lines.append(f"{inner}{render_key(key).ljust(width)} = {render_value(value, inner)}")
    for key, items in nested:
        for item in items:
            if len(lines) > 1:
                lines.append("")
            lines.append(render_block(key, item, inner))
    lines.append(indent + "}")
    return "\n".join(lines)
