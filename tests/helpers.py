"""Builders for small, readable Terraform plan fixtures."""

from __future__ import annotations

import copy
from typing import Any

from src.detector import DriftItem, DriftReport, detect_drift

PROVIDER = "registry.terraform.io/hashicorp/aws"


def sg_rule(description: str, port: int, protocol: str = "tcp", cidrs: tuple[str, ...] = ("0.0.0.0/0",)) -> dict:
    return {
        "cidr_blocks": list(cidrs),
        "description": description,
        "from_port": port,
        "ipv6_cidr_blocks": [],
        "prefix_list_ids": [],
        "protocol": protocol,
        "security_groups": [],
        "self": False,
        "to_port": port,
    }


def security_group(ingress: list[dict], tags: dict | None = None, **extra: Any) -> dict:
    tags = {"Name": "web-tier-sg"} if tags is None else tags
    state = {
        "arn": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0123456789abcdef0",
        "description": "Ingress for the public web tier",
        "egress": [sg_rule("Allow all outbound traffic", 0, "-1")],
        "id": "sg-0123456789abcdef0",
        "ingress": ingress,
        "name": "web-tier-sg",
        "owner_id": "123456789012",
        "tags": tags,
        "tags_all": dict(tags),
        "vpc_id": "vpc-0a1b2c3d4e5f67890",
    }
    state.update(extra)
    return state


def resource_entry(
    address: str,
    before: Any,
    after: Any,
    *,
    actions: tuple[str, ...] = ("update",),
    module_address: str | None = None,
    index: Any = None,
    before_sensitive: Any = None,
    after_sensitive: Any = None,
    after_unknown: Any = None,
) -> dict:
    parts = address.split(".")
    entry = {
        "address": address,
        "mode": "managed",
        "type": parts[-2],
        "name": parts[-1].split("[")[0],
        "provider_name": PROVIDER,
        "change": {
            "actions": list(actions),
            "before": copy.deepcopy(before),
            "after": copy.deepcopy(after),
            "after_unknown": after_unknown or {},
            "before_sensitive": before_sensitive or {},
            "after_sensitive": after_sensitive or {},
        },
    }
    if module_address:
        entry["module_address"] = module_address
    if index is not None:
        entry["index"] = index
    return entry


def make_plan(drift: list[dict] = (), changes: list[dict] = (), timestamp: str = "2026-11-04T06:00:00Z") -> dict:
    return {
        "format_version": "1.2",
        "terraform_version": "1.9.8",
        "timestamp": timestamp,
        "resource_drift": list(drift),
        "resource_changes": list(changes),
    }


def drift_plan(address: str, state: Any, live: Any, config: Any | None = None, **kwargs: Any) -> dict:
    """A normal plan where ``address`` drifted from ``state`` to ``live`` and the code says ``config``."""
    config = state if config is None else config
    drift = resource_entry(address, state, live, **kwargs)
    kwargs.pop("actions", None)
    revert = resource_entry(address, live, config, actions=("update",) if live != config else ("no-op",), **kwargs)
    return make_plan([drift], [revert])


def drift_report(address: str, state: Any, live: Any, config: Any | None = None, **kwargs: Any) -> DriftReport:
    return detect_drift(drift_plan(address, state, live, config, **kwargs))


def drift_item(address: str, state: Any, live: Any, config: Any | None = None, **kwargs: Any) -> DriftItem:
    report = drift_report(address, state, live, config, **kwargs)
    assert len(report.items) == 1, report.items
    return report.items[0]
