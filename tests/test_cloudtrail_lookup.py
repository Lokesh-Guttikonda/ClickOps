from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from src.cloudtrail_lookup import (
    AwsCliCloudTrailBackend,
    CloudTrailError,
    CloudTrailLookup,
    MockCloudTrailBackend,
    build_backend,
    parse_lookup_event,
    parse_principal_patterns,
    parse_time,
)
from src.detector import detect_drift

from .conftest import EXAMPLES

PLAN_TIME = datetime(2026, 11, 4, 6, 0, tzinfo=timezone.utc)
SG_ID = "sg-0123456789abcdef0"


@pytest.fixture
def sg_item(example_plan):
    return detect_drift(example_plan).actionable_items[0]


def raw_event(
    identity: dict,
    *,
    name="ModifySecurityGroupRules",
    when="2026-11-03T22:47:12Z",
    agent="aws-cli/2.17.0",
    read_only=False,
    resources=(SG_ID,),
    event_id="evt-1",
    extra: dict | None = None,
) -> dict:
    detail = {
        "userIdentity": identity,
        "eventTime": when,
        "eventSource": "ec2.amazonaws.com",
        "eventName": name,
        "awsRegion": "eu-west-1",
        "sourceIPAddress": "198.51.100.7",
        "userAgent": agent,
        "requestParameters": {"GroupId": SG_ID},
        "readOnly": read_only,
        **(extra or {}),
    }
    return {
        "EventId": event_id,
        "EventName": name,
        "ReadOnly": str(read_only).lower(),
        "EventTime": when,
        "Username": identity.get("userName", "someone"),
        "Resources": [{"ResourceType": "AWS::EC2::SecurityGroup", "ResourceName": r} for r in resources],
        "CloudTrailEvent": json.dumps(detail),
    }


def test_parse_console_event_by_iam_user(example_events):
    event = parse_lookup_event(example_events["Events"][0])
    assert event.actor == "admin-hotfix"
    assert event.identity_type == "IAMUser"
    assert event.principal_arn == "arn:aws:iam::123456789012:user/admin-hotfix"
    assert event.event_name == "ModifySecurityGroupRules"
    assert event.event_time == datetime(2026, 11, 3, 22, 47, 12, tzinfo=timezone.utc)
    assert event.via_console and event.channel == "AWS Console"
    assert event.source_ip == "203.0.113.42"
    assert event.mfa_authenticated is True
    assert event.references(SG_ID)


def test_parse_sso_assumed_role_event():
    identity = {
        "type": "AssumedRole",
        "arn": "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AdministratorAccess_abc123/jane@example.com",
        "sessionContext": {
            "sessionIssuer": {"type": "Role", "userName": "AWSReservedSSO_AdministratorAccess_abc123"},
            "attributes": {"mfaAuthenticated": "false"},
        },
    }
    event = parse_lookup_event(raw_event(identity))
    assert event.actor == "jane@example.com"
    assert event.role_name == "AWSReservedSSO_AdministratorAccess_abc123"
    assert event.channel == "AWS CLI"
    assert event.mfa_authenticated is False


@pytest.mark.parametrize(
    ("identity", "actor"),
    [
        ({"type": "Root", "arn": "arn:aws:iam::123456789012:root"}, "root"),
        ({"type": "FederatedUser", "arn": "arn:aws:sts::123456789012:federated-user/bob"}, "bob"),
        ({"type": "AWSService", "invokedBy": "autoscaling.amazonaws.com"}, "autoscaling.amazonaws.com"),
    ],
)
def test_other_identity_types(identity, actor):
    assert parse_lookup_event(raw_event(identity)).actor == actor


def test_channels_from_user_agent():
    user = {"type": "IAMUser", "userName": "u"}
    agents = {
        "Boto3/1.35.0 Python/3.12": "AWS SDK",
        "APN/1.0 HashiCorp/1.0 Terraform/1.9.8 terraform-provider-aws/5.72.1": "Terraform",
        "cloudformation.amazonaws.com": "CloudFormation",
        "signin.amazonaws.com": "AWS Console",
    }
    for agent, channel in agents.items():
        assert parse_lookup_event(raw_event(user, agent=agent)).channel == channel


def test_parse_time_formats():
    assert parse_time("2026-11-03T22:47:12Z") == datetime(2026, 11, 3, 22, 47, 12, tzinfo=timezone.utc)
    assert parse_time("2026-11-03T22:47:12+00:00").tzinfo is not None
    assert parse_time(0) == datetime(1970, 1, 1, tzinfo=timezone.utc)


def test_example_attribution_finds_admin_hotfix(sg_item):
    lookup = CloudTrailLookup(MockCloudTrailBackend(EXAMPLES / "cloudtrail_events.json"))
    attribution = lookup.attribute(sg_item, end=PLAN_TIME)
    assert attribution.primary is not None
    assert attribution.primary.actor == "admin-hotfix"
    assert attribution.primary.event_name == "ModifySecurityGroupRules"
    assert attribution.confidence == "high"
    # the read-only Describe call and Terraform's own apply were filtered out
    assert attribution.discarded == 2
    assert [e.event_name for e in attribution.events] == ["ModifySecurityGroupRules"]


def test_events_outside_the_lookback_window_are_ignored(sg_item):
    lookup = CloudTrailLookup(MockCloudTrailBackend(EXAMPLES / "cloudtrail_events.json"), lookback=timedelta(hours=1))
    attribution = lookup.attribute(sg_item, end=PLAN_TIME)
    assert attribution.primary is None and attribution.confidence == "none"
    assert "last 1h" in attribution.note


def test_ignored_principals(sg_item):
    backend = MockCloudTrailBackend(EXAMPLES / "cloudtrail_events.json")
    attribution = CloudTrailLookup(backend, ignore_principals=["admin-*"]).attribute(sg_item, end=PLAN_TIME)
    assert attribution.primary is None
    by_arn = CloudTrailLookup(backend, ignore_principals=["arn:aws:iam::*:user/admin-hotfix"])
    assert by_arn.attribute(sg_item, end=PLAN_TIME).primary is None


def test_terraform_events_can_be_included(sg_item):
    backend = MockCloudTrailBackend(EXAMPLES / "cloudtrail_events.json")
    attribution = CloudTrailLookup(backend, include_terraform=True).attribute(sg_item, end=PLAN_TIME)
    assert {e.event_name for e in attribution.events} == {"ModifySecurityGroupRules", "AuthorizeSecurityGroupIngress"}
    assert attribution.primary.event_name == "ModifySecurityGroupRules"  # most recent wins


def test_unexpected_event_names_lower_the_confidence(sg_item):
    identity = {"type": "IAMUser", "userName": "dev"}
    backend = MockCloudTrailBackend({"Events": [raw_event(identity, name="SomethingElse")]})
    attribution = CloudTrailLookup(backend).attribute(sg_item, end=PLAN_TIME)
    assert attribution.primary.actor == "dev" and attribution.confidence == "medium"


def test_falls_back_to_event_name_search_when_resource_lookup_is_empty(sg_item):
    event = raw_event({"type": "IAMUser", "userName": "dev"}, resources=())

    class Backend:
        name = "fake"

        def __init__(self):
            self.queries = []

        def lookup(self, key, value, start, end):
            self.queries.append((key, value))
            return [event] if (key, value) == ("EventName", "ModifySecurityGroupRules") else []

    backend = Backend()
    attribution = CloudTrailLookup(backend).attribute(sg_item, end=PLAN_TIME)
    assert attribution.primary.actor == "dev"
    assert ("ResourceName", SG_ID) in backend.queries
    assert ("EventName", "ModifySecurityGroupRules") in backend.queries


def test_resources_without_an_id_cannot_be_attributed(sg_item):
    sg_item.before, sg_item.after = {}, {}
    attribution = CloudTrailLookup(MockCloudTrailBackend({"Events": []})).attribute(sg_item, end=PLAN_TIME)
    assert attribution.confidence == "none"


def test_aws_cli_backend_command_and_parsing():
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, json.dumps({"Events": [{"EventId": "x"}]}), "")

    backend = AwsCliCloudTrailBackend(region="eu-west-1", profile="audit", runner=runner)
    start = PLAN_TIME - timedelta(days=7)
    assert backend.lookup("ResourceName", SG_ID, start, PLAN_TIME) == [{"EventId": "x"}]
    [cmd] = calls
    assert cmd[:3] == ["aws", "cloudtrail", "lookup-events"]
    attrs = json.loads(cmd[cmd.index("--lookup-attributes") + 1])
    assert attrs == [{"AttributeKey": "ResourceName", "AttributeValue": SG_ID}]
    assert cmd[cmd.index("--start-time") + 1] == "2026-10-28T06:00:00Z"
    assert cmd[cmd.index("--region") + 1] == "eu-west-1"
    assert cmd[cmd.index("--profile") + 1] == "audit"


def test_aws_cli_backend_errors():
    def failing(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 255, "", "An error occurred (AccessDeniedException)")

    with pytest.raises(CloudTrailError, match="AccessDenied"):
        AwsCliCloudTrailBackend(runner=failing).lookup("ResourceName", SG_ID, PLAN_TIME, PLAN_TIME)

    def missing(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])

    with pytest.raises(CloudTrailError, match="AWS CLI"):
        AwsCliCloudTrailBackend(runner=missing).lookup("ResourceName", SG_ID, PLAN_TIME, PLAN_TIME)


def test_build_backend_modes(monkeypatch):
    assert build_backend("off") is None
    assert isinstance(build_backend("auto", events_file=EXAMPLES / "cloudtrail_events.json"), MockCloudTrailBackend)
    with pytest.raises(CloudTrailError, match="cloudtrail-events"):
        build_backend("mock")
    assert isinstance(build_backend("aws", region="us-east-1"), AwsCliCloudTrailBackend)
    monkeypatch.setattr(AwsCliCloudTrailBackend, "available", staticmethod(lambda aws_bin="aws": False))
    assert build_backend("auto") is None
    with pytest.raises(CloudTrailError, match="unknown"):
        build_backend("bogus")


def test_parse_principal_patterns():
    assert parse_principal_patterns(None) == []
    assert parse_principal_patterns(["terraform-ci, deploy-*", "", "arn:aws:iam::*:role/ci\nbot"]) == [
        "terraform-ci",
        "deploy-*",
        "arn:aws:iam::*:role/ci",
        "bot",
    ]
