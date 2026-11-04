from __future__ import annotations

import pytest

from src import hcl
from src.hcl import HclError, NotLiteral, find_resource, object_body, parse, parse_literal, render_block, render_value

from .conftest import EXAMPLES

TRICKY = """
# comment with { braces }
// another { comment
/* block
   comment } */
resource "aws_iam_policy" "p" {
  name = "a { b } ${var.env} }" # trailing }
  policy = <<-EOT
    {"Statement": [{"Effect": "Allow"}]}
    # not a comment }
  EOT
  path = "/"
}

locals {
  ports = [
    80,  # http
    443, // https
  ]
  map = { a = 1, "b.c" = "two" }
}
"""


def test_parses_the_example_file():
    text = (EXAMPLES / "main.tf").read_text()
    doc = parse(text)
    assert [b.type for b in doc.blocks] == ["terraform", "provider", "variable", "variable", "resource", "resource"]
    sg = find_resource(doc, "aws_security_group", "web")
    assert [a.name for a in sg.body.attributes] == ["name", "description", "vpc_id", "tags"]
    assert [b.type for b in sg.body.blocks] == ["ingress", "ingress", "egress"]
    first = sg.body.blocks_of("ingress")[0]
    assert first.body.attribute("from_port").value(text) == "443"
    assert sg.body.attribute("vpc_id").value(text) == "var.vpc_id"
    assert find_resource(doc, "aws_instance", "nope") is None


def test_strings_heredocs_and_comments_do_not_confuse_brace_matching():
    doc = parse(TRICKY)
    policy = find_resource(doc, "aws_iam_policy", "p")
    assert [a.name for a in policy.body.attributes] == ["name", "policy", "path"]
    assert policy.body.attribute("name").value(TRICKY) == '"a { b } ${var.env} }"'
    assert policy.body.attribute("policy").value(TRICKY).startswith("<<-EOT")
    assert policy.body.attribute("path").value(TRICKY) == '"/"'
    local = doc.blocks[1].body
    assert parse_literal(local.attribute("ports").value(TRICKY)) == [80, 443]
    inline = object_body(TRICKY, local.attribute("map"))
    assert [(a.name, a.value(TRICKY)) for a in inline.attributes] == [("a", "1"), ("b.c", '"two"')]


def test_attribute_line_offsets():
    text = "x {\n  a = 1 # note\n  b = 2\n}\n"
    body = parse(text).blocks[0].body
    a = body.attribute("a")
    assert text[a.line_start : a.line_end] == "  a = 1 # note\n"
    assert a.owns_line(text) and a.indent(text) == "  "


@pytest.mark.parametrize(
    "bad",
    [
        'resource "a" "b" {',
        'x = "unterminated\n',
        "x = [1, 2\n",
        'resource "a" "b" { x = <<EOT\nnever closed\n}',
        "= 1",
    ],
)
def test_malformed_hcl_raises(bad):
    with pytest.raises(HclError):
        parse(bad)


@pytest.mark.parametrize(
    ("src", "value"),
    [
        ("443", 443),
        ("-1", -1),
        ("1.5", 1.5),
        ('"tcp"', "tcp"),
        ('"say \\"hi\\"\\n"', 'say "hi"\n'),
        ('"$${literal}"', "${literal}"),
        ("true", True),
        ("null", None),
        ('["a", "b",]', ["a", "b"]),
        ('{\n  Name = "web"\n  "x.y" : 2\n}', {"Name": "web", "x.y": 2}),
        ("[{ a = [1] }]", [{"a": [1]}]),
    ],
)
def test_parse_literal(src, value):
    assert parse_literal(src) == value


@pytest.mark.parametrize(
    "src",
    [
        "var.port",
        '"${var.env}-web"',
        "local.tags",
        "merge(local.a, {})",
        "true ? 1 : 2",
        "[for p in var.ports : p]",
        "aws_vpc.main.id",
        "<<EOT\nx\nEOT",
    ],
)
def test_expressions_are_not_literals(src):
    with pytest.raises(NotLiteral):
        parse_literal(src)


@pytest.mark.parametrize(
    "value",
    [
        8443,
        -1,
        0.25,
        "tcp",
        'quote " and ${not_interpolated} %{x}',
        True,
        None,
        [],
        ["0.0.0.0/0"],
        {"Name": "web", "kubernetes.io/role": "elb"},
        [{"a": 1}, {"b": [True]}],
    ],
)
def test_render_value_round_trips(value):
    assert parse_literal(render_value(value)) == value


def test_render_value_layout():
    assert render_value(["a", "b"]) == '["a", "b"]'
    assert render_value({"Name": "web", "Environment": "prod"}, "  ") == (
        '{\n    Name        = "web"\n    Environment = "prod"\n  }'
    )
    assert hcl.render_string("${x}") == '"$${x}"'


def test_render_block_aligns_attributes():
    rendered = render_block("ingress", {"description": "SSH", "from_port": 22, "cidr_blocks": ["10.0.0.0/8"]}, "  ")
    assert rendered == (
        '  ingress {\n    description = "SSH"\n    from_port   = 22\n    cidr_blocks = ["10.0.0.0/8"]\n  }'
    )
    assert parse(rendered).blocks[0].type == "ingress"
