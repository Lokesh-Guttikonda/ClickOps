"""Deterministic (PROVIDER=mock) patching. LLM providers are covered in test_llm_providers.py."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from src import hcl, hcl_patcher
from src.detector import DriftReport, detect_drift
from src.hcl_patcher import APPLIED, IN_SYNC, SKIPPED, HclPatcher

from .helpers import drift_item, make_plan, resource_entry, security_group, sg_rule

HTTPS, HTTP = sg_rule("HTTPS", 443), sg_rule("HTTP", 80)

SG_HCL = """\
resource "aws_security_group" "web" {
  name        = "web-tier-sg"
  description = "Ingress for the public web tier"
  vpc_id      = var.vpc_id

  # HTTPS for everyone
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "web-tier-sg"
  }
}
"""


def port(rule: dict, value: int) -> dict:
    return {**rule, "from_port": value, "to_port": value}


def run_patch(tmp_path: Path, text: str, *items, **kwargs):
    (tmp_path / "main.tf").write_text(text)
    result = HclPatcher(**kwargs).patch(DriftReport(items=list(items)), tmp_path)
    patched = result.files[0].patched if result.files else text
    return result, patched


def changed_lines(diff: str) -> list[str]:
    return [line for line in diff.splitlines() if line[:1] in "+-" and not line.startswith(("+++", "---"))]


def resource_body(text: str, rtype: str = "aws_security_group", name: str = "web") -> tuple[hcl.Body, str]:
    return hcl.find_resource(hcl.parse(text), rtype, name).body, text


# --------------------------------------------------------------------------- the demo scenario


def test_example_patch_only_touches_the_drifted_lines(example_plan, example_workdir):
    result = HclPatcher().patch(detect_drift(example_plan), example_workdir)

    [fp] = result.files
    assert fp.path == (example_workdir / "main.tf").resolve()
    assert changed_lines(fp.diff()) == [
        "-    from_port   = 443",
        "-    to_port     = 443",
        "+    from_port   = 8443",
        "+    to_port     = 8443",
    ]
    assert [(o.status, o.engine) for o in result.outcomes] == [(APPLIED, "rules"), (APPLIED, "rules")]
    assert fp.stats() == (2, 2)
    assert "= 8443" not in (example_workdir / "main.tf").read_text(), "patch() must not write"

    result.write()
    assert "from_port   = 8443" in (example_workdir / "main.tf").read_text()


def test_patching_is_idempotent(example_plan, example_workdir):
    HclPatcher().patch(detect_drift(example_plan), example_workdir).write()
    again = HclPatcher().patch(detect_drift(example_plan), example_workdir)
    assert again.files == []
    assert {o.status for o in again.outcomes} == {IN_SYNC}


def test_write_to_an_output_dir_leaves_the_source_alone(example_plan, example_workdir, tmp_path):
    result = HclPatcher().patch(detect_drift(example_plan), example_workdir)
    [written] = result.write(tmp_path / "out", root=example_workdir)
    assert written == tmp_path / "out" / "main.tf"
    assert "from_port   = 8443" in written.read_text()
    assert "= 8443" not in (example_workdir / "main.tf").read_text()


# --------------------------------------------------------------------------- nested blocks


def test_the_matching_block_is_patched_regardless_of_state_order(tmp_path):
    # state lists HTTP first; the code lists HTTPS first
    item = drift_item(
        "aws_security_group.web", security_group([HTTP, HTTPS]), security_group([HTTP, port(HTTPS, 8443)])
    )
    result, patched = run_patch(tmp_path, SG_HCL, item)
    body, text = resource_body(patched)
    https, http = body.blocks_of("ingress")
    assert https.body.attribute("from_port").value(text) == "8443"
    assert http.body.attribute("from_port").value(text) == "80"


def test_an_added_rule_becomes_a_new_block(tmp_path):
    ssh = sg_rule("SSH from the office", 22, cidrs=("203.0.113.0/24",))
    item = drift_item("aws_security_group.web", security_group([HTTPS, HTTP]), security_group([HTTPS, HTTP, ssh]))
    result, patched = run_patch(tmp_path, SG_HCL, item)
    assert [o.status for o in result.outcomes] == [APPLIED]
    body, text = resource_body(patched)
    new = body.blocks_of("ingress")[2]
    values = {a.name: hcl.parse_literal(a.value(text)) for a in new.body.attributes}
    assert values == {
        "description": "SSH from the office",
        "cidr_blocks": ["203.0.113.0/24"],
        "from_port": 22,
        "protocol": "tcp",
        "self": False,
        "to_port": 22,
    }
    assert '\n\n  ingress {\n    description = "SSH from the office"' in patched
    # running again finds the block and leaves the file alone
    again, _ = run_patch(tmp_path, patched, item)
    assert again.files == [] and again.outcomes[0].status == IN_SYNC


def test_a_removed_rule_deletes_the_block_and_its_comment(tmp_path):
    item = drift_item("aws_security_group.web", security_group([HTTPS, HTTP]), security_group([HTTP]))
    result, patched = run_patch(tmp_path, SG_HCL, item)
    assert [o.status for o in result.outcomes] == [APPLIED]
    assert "HTTPS" not in patched and "443" not in patched
    assert "\n\n\n" not in patched
    assert '  vpc_id      = var.vpc_id\n\n  ingress {\n    description = "HTTP"' in patched
    hcl.parse(patched)


def test_dynamic_blocks_are_left_for_a_human(tmp_path):
    text = """resource "aws_security_group" "web" {
  dynamic "ingress" {
    for_each = var.rules
    content {
      from_port = ingress.value
    }
  }
}
"""
    item = drift_item("aws_security_group.web", security_group([HTTPS]), security_group([port(HTTPS, 8443)]))
    result, patched = run_patch(tmp_path, text, item)
    assert {o.status for o in result.outcomes} == {SKIPPED}
    assert "dynamic" in result.outcomes[0].reason and not result.outcomes[0].llm_eligible
    assert patched == text


# --------------------------------------------------------------------------- attributes and maps


def test_expressions_are_never_overwritten(tmp_path):
    text = SG_HCL.replace("from_port   = 443", "from_port   = var.https_port")
    item = drift_item(
        "aws_security_group.web", security_group([HTTPS, HTTP]), security_group([port(HTTPS, 8443), HTTP])
    )
    result, patched = run_patch(tmp_path, text, item)
    statuses = {o.change.dotted: (o.status, o.reason) for o in result.outcomes}
    assert statuses["ingress[0].from_port"][0] == SKIPPED
    assert "var.https_port" in statuses["ingress[0].from_port"][1]
    assert statuses["ingress[0].to_port"][0] == APPLIED  # the literal sibling is still fixed
    assert "var.https_port" in patched and "to_port     = 8443" in patched


def test_map_values_are_changed_added_and_removed_in_place(tmp_path):
    text = SG_HCL.replace(
        '    Name = "web-tier-sg"\n', '    Name = "web-tier-sg"\n    Team = "web" # owners\n    Old  = "x"\n'
    )
    state = security_group([HTTPS, HTTP], tags={"Name": "web-tier-sg", "Team": "web", "Old": "x"})
    live = security_group([HTTPS, HTTP], tags={"Name": "web-tier-sg", "Team": "platform", "Owner": "ops"})
    result, patched = run_patch(tmp_path, text, drift_item("aws_security_group.web", state, live))
    assert {o.status for o in result.outcomes} == {APPLIED}
    body, ptext = resource_body(patched)
    assert hcl.parse_literal(body.attribute("tags").value(ptext)) == {
        "Name": "web-tier-sg",
        "Team": "platform",
        "Owner": "ops",
    }
    assert 'Team = "platform" # owners' in patched  # trailing comment kept


def test_single_line_maps_are_rewritten(tmp_path):
    text = 'resource "aws_instance" "web" {\n  ami  = "ami-1"\n  tags = { Name = "web" }\n}\n'
    item = drift_item(
        "aws_instance.web",
        {"id": "i-1", "ami": "ami-1", "tags": {"Name": "web"}},
        {"id": "i-1", "ami": "ami-1", "tags": {"Name": "web", "Env": "prod"}},
    )
    result, patched = run_patch(tmp_path, text, item)
    body, ptext = resource_body(patched, "aws_instance")
    assert hcl.parse_literal(body.attribute("tags").value(ptext)) == {"Name": "web", "Env": "prod"}


def test_missing_attributes_are_inserted_and_aligned(tmp_path):
    text = 'resource "aws_instance" "web" {\n  ami           = "ami-1"\n  instance_type = "t3.micro"\n}\n'
    state = {"id": "i-1", "ami": "ami-1", "instance_type": "t3.micro", "monitoring": None}
    live = {"id": "i-1", "ami": "ami-1", "instance_type": "t3.large", "monitoring": True}
    result, patched = run_patch(tmp_path, text, drift_item("aws_instance.web", state, live))
    assert patched == (
        'resource "aws_instance" "web" {\n'
        '  ami           = "ami-1"\n'
        '  instance_type = "t3.large"\n'
        "  monitoring    = true\n"
        "}\n"
    )


def test_a_whole_map_can_be_added(tmp_path):
    text = 'resource "aws_instance" "web" {}\n'
    item = drift_item("aws_instance.web", {"id": "i-1", "tags": None}, {"id": "i-1", "tags": {"Owner": "ops"}})
    _, patched = run_patch(tmp_path, text, item)
    assert patched == 'resource "aws_instance" "web" {\n  tags = {\n    Owner = "ops"\n  }\n}\n'


def test_removing_an_attribute_on_a_shared_line_is_skipped_for_review(tmp_path):
    text = 'resource "aws_instance" "web" { monitoring = true }\n'
    item = drift_item("aws_instance.web", {"id": "i-1", "monitoring": True}, {"id": "i-1", "monitoring": None})
    result, patched = run_patch(tmp_path, text, item)
    assert result.outcomes[0].status == SKIPPED and result.outcomes[0].llm_eligible
    assert patched == text


# --------------------------------------------------------------------------- things that must not be patched


def test_sensitive_values_are_never_written(tmp_path):
    text = 'resource "aws_db_instance" "main" {\n  password = "old"\n}\n'
    item = drift_item(
        "aws_db_instance.main",
        {"id": "db", "password": "old"},
        {"id": "db", "password": "new"},
        before_sensitive={"password": True},
        after_sensitive={"password": True},
    )
    result, patched = run_patch(tmp_path, text, item)
    assert result.outcomes[0].status == SKIPPED and "sensitive" in result.outcomes[0].reason
    assert patched == text and "new" not in json.dumps(result.to_dict())


def test_count_and_for_each_instances_are_skipped(tmp_path):
    item = drift_item(
        "aws_security_group.web[0]", security_group([HTTPS]), security_group([port(HTTPS, 8443)]), index=0
    )
    result, patched = run_patch(tmp_path, SG_HCL, item)
    assert {o.status for o in result.outcomes} == {SKIPPED}
    assert "count/for_each" in result.outcomes[0].reason


def test_deleted_resources_are_reported_not_patched(tmp_path):
    state = security_group([HTTPS])
    plan = make_plan([resource_entry("aws_security_group.web", state, None, actions=("delete",))])
    (tmp_path / "main.tf").write_text(SG_HCL)
    result = HclPatcher().patch(detect_drift(plan), tmp_path)
    [outcome] = result.outcomes
    assert outcome.change is None and outcome.status == SKIPPED and "terraform apply" in outcome.reason
    assert result.files == []


def test_resources_missing_from_the_code(tmp_path):
    item = drift_item("aws_security_group.other", security_group([HTTPS]), security_group([port(HTTPS, 8443)]))
    result, _ = run_patch(tmp_path, SG_HCL, item)
    assert "not found" in result.outcomes[0].reason


# --------------------------------------------------------------------------- modules


def _module_layout(tmp_path: Path, source: str, manifest: bool) -> DriftReport:
    (tmp_path / "main.tf").write_text(f'module "net" {{\n  source = "{source}"\n}}\n')
    mod = tmp_path / "modules" / "net"
    mod.mkdir(parents=True)
    (mod / "sg.tf").write_text(SG_HCL)
    if manifest:
        meta = tmp_path / ".terraform" / "modules"
        meta.mkdir(parents=True)
        (meta / "modules.json").write_text(
            json.dumps(
                {
                    "Modules": [
                        {"Key": "", "Source": "", "Dir": "."},
                        {
                            "Key": "net",
                            "Source": source,
                            "Dir": "modules/net" if source.startswith(".") else ".terraform/modules/net",
                        },
                    ]
                }
            )
        )
    item = drift_item(
        "module.net.aws_security_group.web",
        security_group([HTTPS, HTTP]),
        security_group([port(HTTPS, 8443), HTTP]),
        module_address="module.net",
    )
    return DriftReport(items=[item])


@pytest.mark.parametrize("manifest", [True, False])
def test_resources_in_local_modules_are_patched_in_the_module(tmp_path, manifest):
    result = HclPatcher().patch(_module_layout(tmp_path, "./modules/net", manifest), tmp_path)
    [fp] = result.files
    assert fp.path == (tmp_path / "modules" / "net" / "sg.tf").resolve()


def test_resources_in_registry_modules_are_skipped(tmp_path):
    report = _module_layout(tmp_path, "terraform-aws-modules/security-group/aws", manifest=True)
    result = HclPatcher().patch(report, tmp_path)
    assert result.files == []
    assert "terraform-aws-modules/security-group/aws" in result.outcomes[0].reason


# --------------------------------------------------------------------------- file handling


def test_crlf_files_stay_crlf(tmp_path):
    item = drift_item(
        "aws_security_group.web", security_group([HTTPS, HTTP]), security_group([port(HTTPS, 8443), HTTP])
    )
    (tmp_path / "main.tf").write_bytes(SG_HCL.replace("\n", "\r\n").encode())
    result = HclPatcher().patch(DriftReport(items=[item]), tmp_path)
    result.write()
    data = (tmp_path / "main.tf").read_bytes()
    assert b"from_port   = 8443\r\n" in data and b"\n" not in data.replace(b"\r\n", b"")


class FakeFmt:
    """Stands in for `terraform fmt -`."""

    def __init__(self, reject: str | None = None, rewrite: str | None = None):
        self.reject, self.rewrite = reject, rewrite

    def __call__(self, cmd, input, **kwargs):
        assert cmd[1:] == ["fmt", "-no-color", "-"]
        if self.reject and self.reject in input:  # e.g. "= 8443": only the patched text has it
            return subprocess.CompletedProcess(cmd, 2, "", "Error: Invalid expression")
        if self.rewrite and "= 8443" in input:
            return subprocess.CompletedProcess(cmd, 0, input + self.rewrite, "")
        return subprocess.CompletedProcess(cmd, 0, input, "")


def test_terraform_fmt_rejection_discards_the_patch(example_plan, example_workdir, monkeypatch):
    monkeypatch.setattr(hcl_patcher.shutil, "which", lambda name: "/usr/bin/terraform")
    patcher = HclPatcher(fmt="auto", runner=FakeFmt(reject="= 8443"))
    result = patcher.patch(detect_drift(example_plan), example_workdir)
    assert result.files == []
    assert any("terraform fmt" in w for w in result.warnings)
    assert {o.status for o in result.outcomes} == {SKIPPED}


def test_terraform_fmt_output_is_adopted_for_canonical_files(example_plan, example_workdir, monkeypatch):
    monkeypatch.setattr(hcl_patcher.shutil, "which", lambda name: "/usr/bin/terraform")
    patcher = HclPatcher(fmt="auto", runner=FakeFmt(rewrite="# formatted\n"))
    [fp] = patcher.patch(detect_drift(example_plan), example_workdir).files
    assert fp.patched.endswith("# formatted\n")
