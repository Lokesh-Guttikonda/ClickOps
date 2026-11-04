# terradrift-ai

**Autonomous Terraform ClickOps drift reconciler.** Someone "fixed" production in the AWS Console
at 11pm. terradrift-ai notices the drift, finds **who** did it in CloudTrail, rewrites the `.tf` file to
match what is actually running, and opens a pull request with an audit table so your team can either
**codify** the change (merge) or **revert** it (close, then `terraform apply`).

[![ci](https://github.com/Lokesh-Guttikonda/ClickOps/actions/workflows/ci.yml/badge.svg)](https://github.com/Lokesh-Guttikonda/ClickOps/actions/workflows/ci.yml)

```
terraform plan ──► detector ──► cloudtrail_lookup ──► hcl_patcher ──► pr_creator
                   what drifted?   who changed it?      fix the .tf      PR + audit table
```

- **$0 to run.** The default patch engine is deterministic and offline. LLMs are optional, and the free
  tiers of Groq and Gemini work.
- **No heavy SDKs.** No boto3 and no LLM SDKs: CloudTrail goes through the AWS CLI, and LLMs through plain `httpx`.
  The offline demo needs **no third-party packages at all**.
- **Surgical edits.** Only the drifted values change. Comments, alignment and unrelated blocks stay byte-for-byte the same.

## Try it in 30 seconds (no AWS account, no API keys)

```bash
git clone https://github.com/Lokesh-Guttikonda/ClickOps.git
```

```bash
cd ClickOps
```

```bash
python scripts/demo_offline.py
```

The demo uses [`examples/drifted_plan.json`](examples/drifted_plan.json), a real-format `terraform show -json`
plan, and [`examples/cloudtrail_events.json`](examples/cloudtrail_events.json), a saved
`aws cloudtrail lookup-events` response. In the scenario, the `admin-hotfix` IAM user opened the console and
changed the HTTPS rule of a security group from 443 to 8443 (`ModifySecurityGroupRules`):

```text
[1/4] Detect drift      examples/drifted_plan.json
      DRIFT aws_security_group.web: 2 attribute(s) changed outside Terraform
        ingress[0].from_port: 443 -> 8443
        ingress[0].to_port: 443 -> 8443

[2/4] Who did it?       CloudTrail (mock: examples/cloudtrail_events.json)
      who:        admin-hotfix (IAMUser arn:aws:iam::123456789012:user/admin-hotfix)
      what:       ModifySecurityGroupRules at 2026-11-03 22:47:12 UTC
      from:       AWS Console, 203.0.113.42, MFA=yes
      confidence: high
      skipped 2 other event(s) on this resource (read-only calls, Terraform's own apply)

[3/4] Patch Terraform   rules (deterministic, offline)
--- a/examples/main.tf
+++ b/examples/main.tf
@@ -41,8 +41,8 @@
   ingress {
     description = "HTTPS from the internet"
-    from_port   = 443
-    to_port     = 443
+    from_port   = 8443
+    to_port     = 8443
     protocol    = "tcp"
     cidr_blocks = ["0.0.0.0/0"]
   }
      wrote demo_output/main.tf

[4/4] Pull request      dry run: nothing is pushed
      title: fix(drift): codify ClickOps change to aws_security_group.web by admin-hotfix
      risk:  MEDIUM
      body:  demo_output/PR_SUMMARY.md  (+ report.json)
```

It then prints the full Markdown pull request. The core of it looks like this:

| Resource | Attribute | Terraform code | Live in AWS | Changed by | When (UTC) | CloudTrail event | Code patch |
|---|---|---|---|---|---|---|---|
| `aws_security_group.web` | `ingress[0].from_port` | `443` | `8443` | **admin-hotfix**<br><sub>IAMUser · AWS Console · 203.0.113.42</sub> | 2026-11-03 22:47:12 | `ModifySecurityGroupRules` | ✅ codified |
| `aws_security_group.web` | `ingress[0].to_port` | `443` | `8443` | **admin-hotfix**<br><sub>IAMUser · AWS Console · 203.0.113.42</sub> | 2026-11-03 22:47:12 | `ModifySecurityGroupRules` | ✅ codified |

The body also has a risk assessment, the diff, the CloudTrail evidence and reviewer instructions.

By default the demo writes the patched file to `demo_output/`, which is git-ignored, so your clone stays clean.
Use `--in-place` to patch `examples/main.tf` itself.
To try an LLM provider, run `PROVIDER=groq GROQ_API_KEY=... python scripts/demo_offline.py`.

## How it works

| Step | Module | What it does |
|---|---|---|
| Detect | [`src/detector.py`](src/detector.py) | Runs `terraform plan -out=tfplan -detailed-exitcode -lock=false` and `terraform show -json tfplan`, then deletes the plan file because it can contain secrets. It diffs `resource_drift` (state vs. live) and keeps only the attributes that `resource_changes` would revert, so computed attributes, `tags_all` and `ignore_changes` don't add noise. Sets such as `ingress` are matched by content, not position. Sensitive values are flagged and masked everywhere. |
| Who | [`src/cloudtrail_lookup.py`](src/cloudtrail_lookup.py) | Queries CloudTrail event history by resource ID and falls back to event-name search when needed. It drops read-only calls, Terraform's own API calls (by user agent) and principals you ignore, such as your CI role. It then picks the most recent event that can change that resource type and reports the IAM user or SSO session, the channel (console, CLI or SDK), the source IP, MFA status and a confidence level. |
| Patch | [`src/hcl_patcher.py`](src/hcl_patcher.py) | Uses a dependency-free HCL reader/writer ([`src/hcl.py`](src/hcl.py)) to locate the resource, including resources in local modules, and edit values in place. It can add and remove map keys, attributes and repeated nested blocks. Expressions (`var.x`, `local.y`, function calls), `dynamic` blocks, sensitive values, `count`/`for_each` instances and registry modules are never overwritten. They are listed under *Needs a human* instead. When `terraform` is installed, `terraform fmt -` validates every patched file. |
| Risk | [`src/risk.py`](src/risk.py) | Offline rules: security group rules opened to `0.0.0.0/0` (critical for all traffic, high for SSH, RDP or databases), IAM and S3 access changes, disabled encryption, capacity and cost changes, and deleted resources. |
| PR | [`src/pr_creator.py`](src/pr_creator.py) | Renders the Markdown, commits to `terradrift/drift-<fingerprint>` and opens the PR through the GitHub REST API. The same drift on the next scheduled run refreshes the existing PR instead of opening a duplicate. A PR that was closed without merging is treated as rejected and is not reopened. |

## Patch engines (`PROVIDER`)

| `PROVIDER` | Cost | What happens | Configuration |
|---|---|---|---|
| `mock` *(default)* | $0, offline | Deterministic rules engine only | none |
| `groq` | free tier | Rules engine first. The LLM patches only what the rules couldn't, and writes reviewer notes. | `GROQ_API_KEY`, model `llama-3.3-70b-versatile` |
| `gemini` | free tier | Same, using Gemini's OpenAI-compatible endpoint | `GEMINI_API_KEY` (or `GOOGLE_API_KEY`), model `gemini-2.5-flash` |
| `anthropic` | paid | Same, using the Claude Messages API | `ANTHROPIC_API_KEY`, model `claude-opus-5-5` |

Common settings:

| Variable | Default | Meaning |
|---|---|---|
| `LLM_MODEL` | per provider | Override the model, for example `gemini-2.5-pro` or `claude-sonnet-5-5`. |
| `LLM_BASE_URL` | per provider | Point `groq` at any OpenAI-compatible `/chat/completions` server, such as Ollama (`http://localhost:11434/v1`), OpenRouter or vLLM. |
| `LLM_PATCH_MODE` | `fallback` | `always` sends every drifted resource to the LLM. Its output is still verified by the rules engine. |
| `LLM_TIMEOUT` | 60s (120s for Anthropic) | Per-request timeout. 429 and 5xx responses are retried with backoff and `Retry-After`. |
| `ANTHROPIC_EFFORT` | `medium` | Sent as `output_config.effort`. Set it to `off` for older models. |
| `ANTHROPIC_FALLBACKS` | `default` | Server-side refusal fallback (`fallbacks: "default"`). Set it to `off` to disable. |
| `TERRADRIFT_FMT` | `auto` | `off` skips `terraform fmt` validation. |

**LLM output is never trusted blindly.** Before an LLM edit is kept, it has to:

- parse as HCL and keep the same `resource` header,
- leave every attribute and block it wasn't asked to touch byte-for-byte identical,
- set every drifted value, verified by re-running the rules engine on its output, and
- avoid replacing a `var.`/`local.` expression with a literal.

If any check fails, the deterministic result is used and the PR shows a warning. An edit that is safe but
can't be verified mechanically is shown in the PR as an *AI-suggested edit (not applied)*, never committed.
LLM failures (rate limits, refusals, outages) never fail the run.

**Privacy:** only the affected resource block and non-sensitive attribute values are sent to the LLM.
CloudTrail identities, IP addresses and secrets never leave the runner.

## CLI

```bash
pip install .
```

```bash
terradrift detect -C infra --fail-on-drift
```

```bash
terradrift reconcile -C infra --dry-run
```

```bash
terradrift reconcile -C infra --create-pr --label drift --ignore-principal 'terraform-ci'
```

```bash
terradrift reconcile -C examples --plan-json examples/drifted_plan.json --cloudtrail-events examples/cloudtrail_events.json --dry-run
```

The first command lists drifted resources and exits 3 if there are any. The second prints the diff and the report without writing anything.
The third patches in place, pushes a branch and opens a PR. The last uses no Terraform and no AWS at all.

Inside a clone you can also run `python -m src ...` without installing. Useful flags:

- `--plan-json FILE`: use an existing `terraform show -json` file.
- `--refresh-only`: run the plan in refresh-only mode.
- `--cloudtrail auto|aws|mock|off`
- `--lookback-hours N`: how far back to search CloudTrail (default 168).
- `--output-dir DIR`: write patched files there instead of in place.
- `--summary-file pr.md`, `--json-file report.json`
- `--base main`, `--draft`, `--fail-on-drift`

Exit codes: `0` ok, `1` error, `3` drift found (with `--fail-on-drift`).

## GitHub Action

[`.github/workflows/drift-check.yml`](.github/workflows/drift-check.yml) runs every 6 hours:

- **Without setup:** it runs the offline demo, so you can see the report in the job summary.
- **With the repository variable `AWS_ROLE_ARN` set:** it plans your real Terraform via GitHub OIDC and opens PRs.
  Optional variables are `AWS_REGION`, `TF_WORKING_DIR`, `TERRADRIFT_PROVIDER` and `TERRADRIFT_IGNORE_PRINCIPALS`.
  Optional secrets are `GROQ_API_KEY`, `GEMINI_API_KEY` and `ANTHROPIC_API_KEY`.

To use it from another repository:

```yaml
permissions:
  contents: write       # push the terradrift/drift-* branch
  pull-requests: write  # open the PR
  id-token: write       # OIDC to AWS

steps:
  - uses: actions/checkout@v4
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123456789012:role/terradrift-readonly
      aws-region: us-east-1
  - uses: hashicorp/setup-terraform@v3
    with:
      terraform_wrapper: false   # the wrapper corrupts `terraform show -json`
  - run: terraform init -input=false -lock=false
    working-directory: infra
  - uses: Lokesh-Guttikonda/ClickOps@main   # pin a tag or commit SHA in production
    env:
      GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}   # only if provider is groq
    with:
      working-directory: infra
      provider: mock                              # or groq / gemini / anthropic
      ignore-principals: terraform-ci             # your CI role's changes are not ClickOps
```

Inputs: `working-directory`, `provider`, `llm-patch-mode`, `cloudtrail`, `cloudtrail-events`, `aws-region`,
`lookback-hours`, `ignore-principals`, `plan-json`, `refresh-only`, `create-pr`, `base-branch`, `labels`,
`draft`, `fail-on-drift`, `github-token`, `python-version`. Outputs: `drift-detected`, `risk`,
`fingerprint`, `pr-url`, `summary-file`.

**AWS permissions:** the role needs the read access `terraform plan` requires (the managed `ReadOnlyAccess`
policy is the simple option), read access to your state backend, and `cloudtrail:LookupEvents`. It never
needs write access to your infrastructure.

**GitHub settings:**

- Enable **Settings → Actions → General → Allow GitHub Actions to create and approve pull requests**.
- PRs opened with the default `GITHUB_TOKEN` don't trigger other workflows. If you want CI to run on drift PRs,
  pass a GitHub App or fine-grained token as `github-token`.

## Limitations

- AWS only for attribution. Detection and patching work for any provider whose drift shows up in `terraform plan`.
- Resources created entirely outside Terraform are invisible to `terraform plan`, so they are not reported.
- CloudTrail event history covers 90 days of management events and can lag by about 5 to 15 minutes.
- Drift in values that come from variables, locals, `dynamic` blocks, registry modules or `count`/`for_each`
  instances is reported for a human rather than patched automatically.
- `.tf.json` files are not patched.

## Development

```bash
pip install -e ".[dev]"
```

```bash
pytest
```

```bash
ruff check . && ruff format --check .
```

The suite runs 100% offline: the network is disabled in `tests/conftest.py`, and LLM and GitHub calls go to
in-process fakes (`httpx.MockTransport`). CI runs it on Python 3.10, 3.12 and 3.13, and also runs the demo
on a bare interpreter to prove it needs no dependencies.

```
.github/workflows/drift-check.yml   scheduled drift detection (demo until AWS is configured)
.github/workflows/ci.yml            lint + tests + demo
action.yml                          reusable composite action
src/detector.py                     terraform plan -> drift items
src/cloudtrail_lookup.py            who made the change
src/hcl.py                          dependency-free HCL reader/writer
src/hcl_patcher.py                  rules engine + Groq/Gemini/Anthropic over httpx
src/risk.py                         offline risk rules
src/pr_creator.py                   Markdown + GitHub PR
src/reconciler.py, src/cli.py       pipeline and `terradrift` CLI
scripts/demo_offline.py             zero-setup demo
examples/                           drifted plan, CloudTrail events, main.tf
tests/                              pytest suite
```
