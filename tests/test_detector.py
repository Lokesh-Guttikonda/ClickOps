from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from src import detector
from src.detector import (
    TerraformError,
    detect_drift,
    diff_values,
    format_path,
    load_plan,
    run_terraform_plan,
    values_equal,
)

from .conftest import EXAMPLES
from .helpers import drift_item, drift_plan, make_plan, resource_entry, security_group, sg_rule

HTTPS, HTTP = sg_rule("HTTPS", 443), sg_rule("HTTP", 80)


def with_port(rule: dict, port: int) -> dict:
    return {**rule, "from_port": port, "to_port": port}


def test_example_plan_finds_the_security_group_port_change(example_plan):
    report = detect_drift(example_plan, source="example")

    assert report.has_drift
    assert report.terraform_version == "1.9.8"
    [item] = report.actionable_items
    assert item.address == "aws_security_group.web"
    assert item.resource_id == "sg-0123456789abcdef0"
    assert [(c.dotted, c.before, c.after) for c in item.actionable_changes] == [
        ("ingress[0].from_port", 443, 8443),
        ("ingress[0].to_port", 443, 8443),
    ]
    # aws_instance.web is a no-op in resource_changes and never drifted
    assert all(i.address != "aws_instance.web" for i in report.items)


def test_load_plan_reads_files_and_rejects_garbage(tmp_path):
    assert load_plan(EXAMPLES / "drifted_plan.json")["format_version"] == "1.2"
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(TerraformError, match="not valid JSON"):
        load_plan(bad)
    with pytest.raises(TerraformError, match="format_version"):
        detect_drift({"resource_drift": []})


def test_computed_mirrors_are_ignored():
    before = security_group([HTTPS], tags={"Name": "web"})
    after = security_group([HTTPS], tags={"Name": "web", "Owner": "ops"})
    item = drift_item("aws_security_group.web", before, after)
    assert [c.dotted for c in item.changes] == ["tags.Owner"]  # tags_all is ignored
    assert item.changes[0].kind == "added"


def test_drift_the_code_does_not_manage_is_informational():
    state = security_group([HTTPS], owner_id="111111111111")
    live = security_group([HTTPS], owner_id="222222222222")
    # the code matches live already (e.g. computed attribute / ignore_changes): plan is a no-op
    report = detect_drift(drift_plan("aws_security_group.web", state, live, config=live))
    [item] = report.items
    assert not item.needs_action
    assert not report.has_drift
    assert [c.dotted for c in item.informational_changes] == ["owner_id"]


def test_only_attributes_the_code_disagrees_with_are_actionable():
    state = security_group([HTTPS], owner_id="111111111111")
    live = security_group([with_port(HTTPS, 8443)], owner_id="222222222222")
    config = security_group([HTTPS], owner_id="222222222222")  # owner_id is computed
    item = drift_item("aws_security_group.web", state, live, config=config)
    assert [c.dotted for c in item.actionable_changes] == ["ingress[0].from_port", "ingress[0].to_port"]
    assert [c.dotted for c in item.informational_changes] == ["owner_id"]


def test_refresh_only_plans_treat_all_drift_as_actionable():
    state, live = security_group([HTTPS]), security_group([with_port(HTTPS, 8443)])
    plan = make_plan([resource_entry("aws_security_group.web", state, live)])  # no resource_changes
    assert detect_drift(plan).has_drift
    plan = drift_plan("aws_security_group.web", state, live, config=live)  # no-op revert...
    assert detect_drift(plan, refresh_only=True).has_drift  # ...but refresh-only says act anyway


def test_unknown_values_after_apply_are_not_counted_as_disagreement():
    state, live = security_group([HTTPS]), security_group([with_port(HTTPS, 8443)])
    drift = resource_entry("aws_security_group.web", state, {**live, "owner_id": "999"})
    config = {**state}
    config.pop("owner_id")
    revert = resource_entry(
        "aws_security_group.web", {**live, "owner_id": "999"}, config, after_unknown={"owner_id": True}
    )
    [item] = detect_drift(make_plan([drift], [revert])).items
    actionable = {c.dotted for c in item.actionable_changes}
    assert "owner_id" not in actionable
    assert "ingress[0].from_port" in actionable


def test_set_elements_are_matched_by_content_not_position():
    state = security_group([HTTPS, HTTP])
    live = security_group([HTTP, with_port(HTTPS, 8443)])  # reordered and modified
    item = drift_item("aws_security_group.web", state, live)
    assert [(c.dotted, c.kind) for c in item.changes] == [
        ("ingress[0].from_port", "modified"),
        ("ingress[0].to_port", "modified"),
    ]


def test_added_and_removed_nested_elements():
    ssh = sg_rule("SSH from anywhere", 22)
    added = drift_item("aws_security_group.web", security_group([HTTPS]), security_group([HTTPS, ssh]))
    assert [(c.dotted, c.kind) for c in added.changes] == [("ingress[1]", "added")]
    assert added.changes[0].after["from_port"] == 22
    assert added.element_after(("ingress", 1)) == ssh

    removed = drift_item("aws_security_group.web", security_group([HTTPS, HTTP]), security_group([HTTPS]))
    assert [(c.dotted, c.kind) for c in removed.changes] == [("ingress[1]", "removed")]
    assert removed.element_after(("ingress", 1)) is None


def test_a_mostly_similar_replacement_is_a_modification():
    # HTTP:80 replaced by SSH:22 shares protocol and CIDRs, so it is reported as an edit
    ssh = sg_rule("SSH from anywhere", 22)
    item = drift_item("aws_security_group.web", security_group([HTTPS, HTTP]), security_group([HTTPS, ssh]))
    assert {c.dotted for c in item.changes} == {"ingress[1].description", "ingress[1].from_port", "ingress[1].to_port"}


def test_element_after_reconstructs_the_live_object():
    item = drift_item("aws_security_group.web", security_group([HTTPS]), security_group([with_port(HTTPS, 8443)]))
    live = item.element_after(("ingress", 0))
    assert live["from_port"] == 8443 and live["description"] == "HTTPS"


def test_sensitive_values_are_flagged_and_masked():
    state = {"id": "db-1", "password": "hunter2", "instance_class": "db.t3.micro"}
    live = {"id": "db-1", "password": "s3cret!", "instance_class": "db.t3.micro"}
    item = drift_item(
        "aws_db_instance.main", state, live, before_sensitive={"password": True}, after_sensitive={"password": True}
    )
    [change] = item.changes
    assert change.sensitive
    assert change.to_dict()["before"] == "(sensitive)"
    assert "hunter2" not in json.dumps(item.to_dict())


def test_deleted_resources_need_action():
    state = security_group([HTTPS])
    plan = make_plan(
        [resource_entry("aws_security_group.web", state, None, actions=("delete",))],
        [resource_entry("aws_security_group.web", None, state, actions=("create",))],
    )
    [item] = detect_drift(plan).actionable_items
    assert item.deleted and item.changes == []


def test_module_and_index_are_captured():
    plan = drift_plan(
        "module.net.aws_security_group.web",
        security_group([HTTPS]),
        security_group([with_port(HTTPS, 8443)]),
        module_address="module.net",
    )
    [item] = detect_drift(plan).items
    assert item.module_address == "module.net" and item.name == "web"


@pytest.mark.parametrize(
    ("a", "b", "equal"),
    [
        (None, [], True),
        ("", None, True),
        ({}, None, True),
        (443, "443", True),
        (["b", "a"], ["a", "b"], True),
        (True, 1, False),
        (False, None, False),
        ({"a": 1, "b": None}, {"a": 1}, True),
        ([{"x": 1}], [{"x": 2}], False),
    ],
)
def test_values_equal(a, b, equal):
    assert values_equal(a, b) is equal


def test_format_path_and_diff():
    assert format_path(("ingress", 0, "from_port")) == "ingress[0].from_port"
    assert format_path(("tags", "Name")) == "tags.Name"
    assert list(diff_values({"a": [1, 2]}, {"a": [2, 1]})) == []
    assert list(diff_values({"a": 1}, {"a": 2})) == [(("a",), 1, 2, "modified")]


# --------------------------------------------------------------------------- terraform plan


class FakeTerraform:
    def __init__(self, plan_exit: int = 2, show_stdout: str | None = None, workdir: Path | None = None):
        self.calls: list[list[str]] = []
        self.plan_exit = plan_exit
        self.show_stdout = show_stdout if show_stdout is not None else json.dumps(make_plan())
        self.workdir = workdir

    def __call__(self, cmd, cwd=None, **kwargs):
        self.calls.append(cmd)
        if cmd[1] == "plan":
            (Path(cwd) / "tfplan").write_text("binary plan")
            return subprocess.CompletedProcess(cmd, self.plan_exit, "", "Error: something broke\n")
        return subprocess.CompletedProcess(cmd, 0, self.show_stdout, "")


@pytest.fixture
def fake_terraform_bin(monkeypatch):
    monkeypatch.setattr(detector.shutil, "which", lambda name: "/usr/local/bin/terraform")


def test_run_terraform_plan_runs_plan_then_show_and_deletes_the_plan(tmp_path, fake_terraform_bin):
    fake = FakeTerraform()
    plan = run_terraform_plan(tmp_path, runner=fake, refresh_only=True, var_files=["prod.tfvars"])
    assert plan["format_version"] == "1.2"
    plan_cmd, show_cmd = fake.calls
    assert plan_cmd[:2] == ["/usr/local/bin/terraform", "plan"]
    for flag in (
        "-detailed-exitcode",
        "-lock=false",
        "-out=tfplan",
        "-input=false",
        "-refresh-only",
        "-var-file=prod.tfvars",
    ):
        assert flag in plan_cmd
    assert show_cmd[1:] == ["show", "-json", "-no-color", "tfplan"]
    assert not (tmp_path / "tfplan").exists(), "binary plans may contain secrets"


def test_run_terraform_plan_failure(tmp_path, fake_terraform_bin):
    with pytest.raises(TerraformError, match="(?s)exit 1.*something broke"):
        run_terraform_plan(tmp_path, runner=FakeTerraform(plan_exit=1))
    assert not (tmp_path / "tfplan").exists()


def test_setup_terraform_wrapper_noise_is_tolerated(tmp_path, fake_terraform_bin):
    noisy = "[command]/usr/bin/terraform show -json tfplan\n" + json.dumps(make_plan()) + "\n::debug::exitcode: 0\n"
    assert run_terraform_plan(tmp_path, runner=FakeTerraform(show_stdout=noisy))["format_version"] == "1.2"
    with pytest.raises(TerraformError, match="terraform_wrapper"):
        run_terraform_plan(tmp_path, runner=FakeTerraform(show_stdout="not json at all"))


def test_missing_terraform_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(detector.shutil, "which", lambda name: None)
    with pytest.raises(TerraformError, match="not found"):
        run_terraform_plan(tmp_path, terraform_bin="definitely-not-terraform")
