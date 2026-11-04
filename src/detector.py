"""Drift detection: run ``terraform plan`` and turn its JSON into drift items.

Terraform's JSON plan (``terraform show -json tfplan``) carries two lists we care about:

``resource_drift``
    Objects whose real-world state differs from the Terraform state, i.e. something
    changed them outside Terraform. ``before`` is the old state, ``after`` is live.
``resource_changes``
    What ``terraform apply`` would do. For a drifted object in a normal plan this is the
    *revert*: ``before`` is live, ``after`` is what the code asks for.

An attribute is *actionable* when it drifted **and** the code still disagrees with the
live value (so ``apply`` would revert it). Drift that the configuration doesn't manage
(computed attributes, ``ignore_changes``) is reported as informational only.
"""

from __future__ import annotations

import contextlib
import copy
import json
import logging
import os
import shutil
import subprocess
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

PathT = tuple  # tuple[str | int, ...]

#: Attributes that are computed mirrors or bookkeeping and never belong in HCL.
DEFAULT_IGNORED_ATTRIBUTES = frozenset({"id", "arn", "tags_all", "timeouts"})

_MISSING = object()


class TerraformError(RuntimeError):
    """``terraform`` could not be run or its output could not be read."""


# --------------------------------------------------------------------------- values


def format_path(path: Sequence[str | int]) -> str:
    """``("ingress", 0, "from_port")`` -> ``ingress[0].from_port``."""
    out = ""
    for part in path:
        if isinstance(part, int):
            out += f"[{part}]"
        elif out:
            out += f".{part}"
        else:
            out = str(part)
    return out


def _is_empty(value: Any) -> bool:
    return value is None or value is _MISSING or value == "" or value == [] or value == {}


def values_equal(a: Any, b: Any) -> bool:
    """Semantic equality for Terraform values.

    ``null``, ``""``, ``[]`` and ``{}`` are interchangeable (providers normalise them
    differently), lists of scalars compare as sets (Terraform sets are unordered), and a
    number equals its string form (HCL ``"443"`` vs JSON ``443``).
    """
    if _is_empty(a) and _is_empty(b):
        return True
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, (int, float)) and isinstance(b, str):
        return str(a) == b
    if isinstance(a, str) and isinstance(b, (int, float)):
        return a == str(b)
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return False
        if all(values_equal(x, y) for x, y in zip(a, b, strict=True)):
            return True
        scalars = (str, int, float)
        if all(isinstance(x, scalars) for x in a + b):
            return sorted(map(str, a)) == sorted(map(str, b))
        return False
    if isinstance(a, dict) and isinstance(b, dict):
        return all(values_equal(a.get(k), b.get(k)) for k in set(a) | set(b))
    return a == b


def get_path(value: Any, path: Sequence[str | int], default: Any = None) -> Any:
    for part in path:
        if isinstance(part, int):
            if not isinstance(value, list) or part >= len(value):
                return default
            value = value[part]
        else:
            if not isinstance(value, dict) or part not in value:
                return default
            value = value[part]
    return value


def set_path(value: Any, path: Sequence[str | int], new: Any) -> bool:
    """Set ``value[path] = new`` in place; returns False if the path doesn't exist."""
    if not path:
        return False
    parent = get_path(value, path[:-1], _MISSING)
    last = path[-1]
    if isinstance(last, int) and isinstance(parent, list) and last < len(parent):
        parent[last] = new
        return True
    if isinstance(last, str) and isinstance(parent, dict):
        parent[last] = new
        return True
    return False


def is_marked(tree: Any, path: Sequence[str | int]) -> bool:
    """Walk a ``*_sensitive`` / ``after_unknown`` tree; True if any prefix is marked."""
    node = tree
    for part in path:
        if node is True:
            return True
        if isinstance(part, int) and isinstance(node, list) and part < len(node):
            node = node[part]
        elif isinstance(part, str) and isinstance(node, dict):
            node = node.get(part)
        else:
            return False
    return node is True


def _similarity(a: dict, b: dict) -> float:
    keys = set(a) | set(b)
    if not keys:
        return 1.0
    return sum(1 for k in keys if values_equal(a.get(k), b.get(k))) / len(keys)


def _match_elements(before: list, after: list) -> tuple[list[tuple[int, int]], list[int], list[int]]:
    """Pair up elements of two lists of objects (sets are unordered, so match by content)."""
    pairs: list[tuple[int, int]] = []
    free_after = set(range(len(after)))
    free_before = []
    for i, elem in enumerate(before):
        exact = next((j for j in sorted(free_after) if values_equal(elem, after[j])), None)
        if exact is None:
            free_before.append(i)
        else:
            pairs.append((i, exact))
            free_after.discard(exact)
    scored = sorted(
        ((_similarity(before[i], after[j]), i, j) for i in free_before for j in free_after),
        key=lambda t: (-t[0], t[1], t[2]),
    )
    used_before: set[int] = set()
    for score, i, j in scored:
        if score < 0.5 or i in used_before or j not in free_after:
            continue
        pairs.append((i, j))
        used_before.add(i)
        free_after.discard(j)
    removed = [i for i in free_before if i not in used_before]
    return sorted(pairs), removed, sorted(free_after)


def diff_values(before: Any, after: Any, path: PathT = ()) -> Iterator[tuple[PathT, Any, Any, str]]:
    """Yield ``(path, before, after, kind)`` for every difference.

    Objects recurse per key, lists of objects recurse per (content-matched) element,
    anything else -- including lists of scalars -- is compared as a single leaf.
    List indices in yielded paths refer to ``before`` (or ``after`` for added elements).
    """
    if isinstance(before, dict) and isinstance(after, dict):
        for key in list(before) + [k for k in after if k not in before]:
            yield from diff_values(before.get(key), after.get(key), path + (key,))
        return
    if (
        isinstance(before, list)
        and isinstance(after, list)
        and (before or after)
        and all(isinstance(x, dict) for x in before + after)
    ):
        pairs, removed, added = _match_elements(before, after)
        for i, j in pairs:
            yield from diff_values(before[i], after[j], path + (i,))
        for i in removed:
            yield path + (i,), before[i], None, "removed"
        for j in added:
            yield path + (j,), None, after[j], "added"
        return
    if not values_equal(before, after):
        kind = "added" if _is_empty(before) else "removed" if _is_empty(after) else "modified"
        yield path, before, after, kind


def _normalise(path: PathT) -> PathT:
    return tuple("*" if isinstance(p, int) else p for p in path)


# --------------------------------------------------------------------------- model


@dataclass(frozen=True)
class AttributeChange:
    """One attribute that differs between Terraform state and live infrastructure."""

    path: PathT
    before: Any  # value Terraform last wrote (what the code describes)
    after: Any  # value currently live in the cloud
    kind: str = "modified"  # modified | added | removed
    sensitive: bool = False
    actionable: bool = True

    @property
    def dotted(self) -> str:
        return format_path(self.path)

    def to_dict(self) -> dict[str, Any]:
        mask = "(sensitive)"
        return {
            "path": self.dotted,
            "before": mask if self.sensitive else self.before,
            "after": mask if self.sensitive else self.after,
            "kind": self.kind,
            "sensitive": self.sensitive,
            "actionable": self.actionable,
        }


@dataclass
class DriftItem:
    """A resource whose live state differs from the Terraform state."""

    address: str
    type: str
    name: str
    module_address: str | None
    index: Any
    provider_name: str
    drift_actions: list[str]
    planned_actions: list[str]
    before: Any
    after: Any
    changes: list[AttributeChange] = field(default_factory=list)

    @property
    def deleted(self) -> bool:
        return "delete" in self.drift_actions and not self.after

    @property
    def actionable_changes(self) -> list[AttributeChange]:
        return [c for c in self.changes if c.actionable]

    @property
    def informational_changes(self) -> list[AttributeChange]:
        return [c for c in self.changes if not c.actionable]

    @property
    def needs_action(self) -> bool:
        return self.deleted or bool(self.actionable_changes)

    def _attr(self, name: str) -> str | None:
        for obj in (self.after, self.before):
            if isinstance(obj, dict) and obj.get(name):
                return str(obj[name])
        return None

    @property
    def resource_id(self) -> str | None:
        return self._attr("id")

    @property
    def arn(self) -> str | None:
        return self._attr("arn")

    def element_after(self, list_path: PathT) -> dict | None:
        """Live value of a nested list element, e.g. ``("ingress", 0)``.

        Reconstructed from the old state element plus this item's changes beneath it, so
        indices stay consistent with :attr:`AttributeChange.path`.
        """
        for change in self.changes:
            if change.path == list_path and change.kind in ("added", "removed"):
                return change.after
        element = get_path(self.before, list_path)
        if not isinstance(element, dict):
            return None
        result = copy.deepcopy(element)
        depth = len(list_path)
        for change in self.changes:
            if len(change.path) > depth and change.path[:depth] == list_path:
                set_path(result, change.path[depth:], copy.deepcopy(change.after))
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "type": self.type,
            "name": self.name,
            "module_address": self.module_address,
            "resource_id": self.resource_id,
            "deleted": self.deleted,
            "drift_actions": self.drift_actions,
            "planned_actions": self.planned_actions,
            "changes": [c.to_dict() for c in self.changes],
        }


@dataclass
class DriftReport:
    items: list[DriftItem]
    terraform_version: str | None = None
    timestamp: str | None = None
    source: str = "terraform plan"

    @property
    def actionable_items(self) -> list[DriftItem]:
        return [item for item in self.items if item.needs_action]

    @property
    def has_drift(self) -> bool:
        return bool(self.actionable_items)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "terraform_version": self.terraform_version,
            "timestamp": self.timestamp,
            "has_drift": self.has_drift,
            "items": [item.to_dict() for item in self.items],
        }


# --------------------------------------------------------------------------- detection


def detect_drift(
    plan: dict[str, Any],
    *,
    refresh_only: bool = False,
    ignored_attributes: frozenset[str] | set[str] = DEFAULT_IGNORED_ATTRIBUTES,
    source: str = "terraform plan",
) -> DriftReport:
    """Build a :class:`DriftReport` from a Terraform JSON plan."""
    if not isinstance(plan, dict) or "format_version" not in plan:
        raise TerraformError("not a Terraform JSON plan (missing format_version)")

    planned: dict[str, dict] = {
        rc["address"]: rc for rc in plan.get("resource_changes") or [] if rc.get("mode") == "managed"
    }
    items: list[DriftItem] = []
    for drift in plan.get("resource_drift") or []:
        if drift.get("mode", "managed") != "managed":
            continue
        change = drift.get("change") or {}
        before, after = change.get("before"), change.get("after")
        address = drift["address"]
        rc = planned.get(address)
        planned_actions = list((rc or {}).get("change", {}).get("actions") or [])

        # Which attributes does the configuration disagree with? (None = unknown.)
        config_disagrees: set[PathT] | None = None
        if rc is not None and not refresh_only:
            rc_change = rc.get("change") or {}
            config_disagrees = set()
            if planned_actions != ["no-op"]:
                unknown = rc_change.get("after_unknown") or {}
                for path, _, _, _ in diff_values(rc_change.get("before"), rc_change.get("after")):
                    if not is_marked(unknown, path):
                        config_disagrees.add(_normalise(path))

        changes = []
        for path, old, new, kind in diff_values(before, after):
            if not path or path[0] in ignored_attributes:
                continue
            sensitive = is_marked(change.get("before_sensitive"), path) or is_marked(
                change.get("after_sensitive"), path
            )
            norm = _normalise(path)
            actionable = config_disagrees is None or any(
                p[: len(norm)] == norm or norm[: len(p)] == p for p in config_disagrees
            )
            changes.append(AttributeChange(path, old, new, kind, sensitive, actionable))

        item = DriftItem(
            address=address,
            type=drift.get("type", ""),
            name=drift.get("name", ""),
            module_address=drift.get("module_address"),
            index=drift.get("index"),
            provider_name=drift.get("provider_name", ""),
            drift_actions=list(change.get("actions") or []),
            planned_actions=planned_actions,
            before=before,
            after=after,
            changes=changes,
        )
        if item.changes or item.deleted:
            items.append(item)
    return DriftReport(
        items=items,
        terraform_version=plan.get("terraform_version"),
        timestamp=plan.get("timestamp"),
        source=source,
    )


def load_plan(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Read the output of ``terraform show -json tfplan`` from a file."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TerraformError(f"{path} is not valid JSON: {exc}") from exc


def _parse_json_output(stdout: str) -> dict[str, Any]:
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        # hashicorp/setup-terraform's wrapper (terraform_wrapper: true) adds extra lines.
        start, end = stdout.find("{"), stdout.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(stdout[start : end + 1])
            except json.JSONDecodeError:
                pass
    raise TerraformError(
        "could not parse `terraform show -json` output; if you use hashicorp/setup-terraform "
        "set `terraform_wrapper: false`"
    )


Runner = Callable[..., subprocess.CompletedProcess]


def run_terraform_plan(
    workdir: str | os.PathLike[str],
    *,
    terraform_bin: str = "terraform",
    refresh_only: bool = False,
    plan_file: str = "tfplan",
    var_files: Sequence[str] = (),
    extra_args: Sequence[str] = (),
    lock: bool = False,
    timeout: float = 1800,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Run ``terraform plan -out=tfplan`` + ``terraform show -json tfplan``.

    The plan runs with ``-lock=false`` by default because drift detection is read-only and
    must not block real applies. The binary plan file is deleted afterwards: it can contain
    secrets.
    """
    workdir = Path(workdir)
    executable = shutil.which(terraform_bin) or (terraform_bin if Path(terraform_bin).is_file() else None)
    if executable is None:
        raise TerraformError(f"`{terraform_bin}` not found on PATH; install Terraform or pass --plan-json")
    env = {**os.environ, "TF_IN_AUTOMATION": "1", "TF_INPUT": "0"}
    cmd = [
        executable,
        "plan",
        "-input=false",
        "-no-color",
        "-detailed-exitcode",
        f"-lock={'true' if lock else 'false'}",
        f"-out={plan_file}",
    ]
    if refresh_only:
        cmd.append("-refresh-only")
    cmd += [f"-var-file={vf}" for vf in var_files]
    cmd += list(extra_args)

    log.info("running %s in %s", " ".join(cmd[1:]), workdir)
    try:
        plan = runner(cmd, cwd=workdir, capture_output=True, text=True, timeout=timeout, env=env)
        # -detailed-exitcode: 0 = no changes, 1 = error, 2 = changes present
        if plan.returncode not in (0, 2):
            tail = "\n".join((plan.stderr or plan.stdout or "").strip().splitlines()[-25:])
            raise TerraformError(f"terraform plan failed (exit {plan.returncode}):\n{tail}")
        show = runner(
            [executable, "show", "-json", "-no-color", plan_file],
            cwd=workdir,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        if show.returncode != 0:
            raise TerraformError(f"terraform show failed (exit {show.returncode}): {show.stderr.strip()}")
        return _parse_json_output(show.stdout)
    except subprocess.TimeoutExpired as exc:
        raise TerraformError(f"terraform timed out after {timeout:.0f}s") from exc
    finally:
        with contextlib.suppress(OSError):
            (workdir / plan_file).unlink()
