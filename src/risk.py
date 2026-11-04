"""Deterministic, offline risk rules for drift (no LLM needed)."""

from __future__ import annotations

from dataclasses import dataclass

from .detector import DriftItem, DriftReport, values_equal

LEVELS = ("info", "low", "medium", "high", "critical")

SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    135: "MS RPC",
    445: "SMB",
    1433: "SQL Server",
    1521: "Oracle",
    2375: "Docker API",
    2379: "etcd",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5601: "Kibana",
    5900: "VNC",
    6379: "Redis",
    9092: "Kafka",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}
WORLD = {"0.0.0.0/0", "::/0"}
_SG_INLINE = "aws_security_group"
_SG_RULES = {"aws_security_group_rule", "aws_vpc_security_group_ingress_rule"}
_CAPACITY_ATTRS = {"instance_type", "instance_class", "allocated_storage", "desired_capacity", "max_size", "min_size"}


@dataclass(frozen=True)
class RiskFinding:
    level: str
    address: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"level": self.level, "address": self.address, "message": self.message}


def overall_level(findings: list[RiskFinding]) -> str:
    if not findings:
        return "none"
    return max((f.level for f in findings), key=LEVELS.index)


def _ports(rule: dict) -> tuple[str, int | None, int | None]:
    protocol = str(rule.get("protocol", rule.get("ip_protocol", "")) or "")
    return protocol, rule.get("from_port"), rule.get("to_port")


def _port_label(protocol: str, low: int | None, high: int | None) -> str:
    if protocol in ("-1", "all"):
        return "all traffic"
    if low is None:
        return protocol or "?"
    return f"{protocol}/{low}" if low == high else f"{protocol}/{low}-{high}"


def _exposure(address: str, rule: dict, previous: dict | None) -> RiskFinding:
    cidrs = set(rule.get("cidr_blocks") or []) | set(rule.get("ipv6_cidr_blocks") or [])
    for key in ("cidr_ipv4", "cidr_ipv6"):
        if rule.get(key):
            cidrs.add(rule[key])
    protocol, low, high = _ports(rule)
    label = _port_label(protocol, low, high)
    world = sorted(cidrs & WORLD)
    was = ""
    if previous:
        old = _port_label(*_ports(previous))
        if old != label:
            was = f" (previously {old})"
    if not world:
        return RiskFinding("low", address, f"ingress rule changed: now {label}{was}")
    source = ", ".join(world)
    if protocol in ("-1", "all") or (low == 0 and high == 65535):
        return RiskFinding("critical", address, f"ingress now allows ALL traffic from {source}{was}")
    exposed = [
        f"{name} ({port})"
        for port, name in SENSITIVE_PORTS.items()
        if low is not None and high is not None and low <= port <= high
    ]
    if exposed:
        return RiskFinding("high", address, f"ingress exposes {', '.join(exposed)} to {source}{was}")
    hint = ""
    if was and low not in (80, 443):
        hint = (
            ". A non-standard port opened to the internet is a classic emergency hotfix; "
            "confirm it is still needed and fronted by TLS/WAF"
        )
    return RiskFinding("medium", address, f"ingress now allows {label} from {source}{was}{hint}")


def _security_group_findings(item: DriftItem) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    touched = sorted({c.path[:2] for c in item.actionable_changes if len(c.path) >= 2 and isinstance(c.path[1], int)})
    for list_path in touched:
        direction = list_path[0]
        before = None
        if isinstance(item.before, dict) and isinstance(item.before.get(direction), list):
            elements = item.before[direction]
            before = elements[list_path[1]] if list_path[1] < len(elements) else None
        after = item.element_after(list_path)
        added = any(c.path == list_path and c.kind == "added" for c in item.actionable_changes)
        if added:
            before = None
        if direction == "egress":
            findings.append(RiskFinding("low", item.address, "egress rule changed outside Terraform"))
        elif after is None:
            findings.append(
                RiskFinding("low", item.address, "ingress rule removed; traffic that relied on it will break")
            )
        else:
            findings.append(_exposure(item.address, after, before))
    return findings


def assess_item(item: DriftItem) -> list[RiskFinding]:
    address = item.address
    if item.deleted:
        return [
            RiskFinding(
                "high",
                address,
                "resource was deleted outside Terraform; dependants may be broken and "
                "`terraform apply` will recreate it",
            )
        ]
    changes = item.actionable_changes
    if not changes:
        return []
    findings: list[RiskFinding] = []
    if item.type == _SG_INLINE:
        findings += _security_group_findings(item)
    elif item.type in _SG_RULES and isinstance(item.after, dict) and item.after.get("type", "ingress") == "ingress":
        findings.append(_exposure(address, item.after, item.before if isinstance(item.before, dict) else None))
    if item.type.startswith("aws_iam_"):
        findings.append(RiskFinding("high", address, "IAM configuration changed outside Terraform; review privileges"))
    if item.type.startswith("aws_s3_bucket") and any(
        any(word in c.dotted for word in ("policy", "acl", "public", "block_public")) for c in changes
    ):
        findings.append(RiskFinding("high", address, "S3 access configuration changed; check for public exposure"))
    for change in changes:
        dotted = change.dotted.lower()
        if ("encrypt" in dotted or "kms" in dotted) and not values_equal(change.after, change.before):
            if change.after in (False, None, "", []):
                findings.append(RiskFinding("high", address, f"encryption setting `{change.dotted}` was disabled"))
            else:
                findings.append(RiskFinding("medium", address, f"encryption setting `{change.dotted}` changed"))
        if change.path and change.path[0] in _CAPACITY_ATTRS:
            findings.append(
                RiskFinding(
                    "low",
                    address,
                    f"`{change.dotted}` changed from {change.before!r} to {change.after!r} (cost/capacity impact)",
                )
            )
    if not findings:
        if all(c.path and c.path[0] == "tags" for c in changes):
            findings.append(RiskFinding("info", address, "tag-only change"))
        else:
            findings.append(RiskFinding("low", address, "configuration changed outside Terraform"))
    return findings


def assess_risk(report: DriftReport) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    for item in report.actionable_items:
        findings += assess_item(item)
    return sorted(findings, key=lambda f: -LEVELS.index(f.level))
