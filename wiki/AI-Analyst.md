# AI Analyst

Ask questions about an audit report in plain language: "what should I fix first?", "which Drive settings failed and why?", "what changed since last month?". The analyst is a chat session with an LLM that can call 13 read-only tools over your saved reports. It works from the JSON reports the auditor already wrote -- it never calls Google APIs and cannot change your tenant.

It is available as a terminal REPL (`gws-auditor analyst`) and as a page in the [Dashboard](Dashboard).

## Before you enable it: what leaves your machine

The analyst sends audit data to the LLM provider you choose. Each question sends the conversation so far plus the output of whatever tools the model called, and those tool results are taken from your report: check results, actual values, per-OU details, and inventory data. That routinely includes **user email addresses, group names, OAuth app names and client ids, device models, domain names, your customer id, and a precise list of your tenant's security weaknesses**.

Decide accordingly:

- Use a provider your organization has approved for confidential data, under an agreement that covers retention and training use.
- **Amazon Bedrock** keeps requests inside your own AWS account and region.
- `base_url` lets the OpenAI provider talk to any OpenAI-compatible endpoint, including a self-hosted model.
- If none of that is acceptable, do not enable the analyst. Nothing else in the auditor depends on it, and no data is sent anywhere unless you start it.

## Install

```bash
pip install "gws-security-auditor[ai-anthropic]"   # Anthropic only
pip install "gws-security-auditor[ai-openai]"      # OpenAI (or an OpenAI-compatible endpoint)
pip install "gws-security-auditor[ai-bedrock]"     # Amazon Bedrock (boto3)
pip install "gws-security-auditor[ai]"             # all three
```

## Run

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
gws-auditor analyst --provider anthropic

gws-auditor analyst --provider openai --model gpt-4o --report audit_20260920_101500.json
```

| Option | Default | Description |
|--------|---------|-------------|
| `--reports-dir` | `./reports` | Directory containing `audit_*.json` reports |
| `--report` | most recent | Report file to analyze |
| `--provider` | from config (`openai`) | `openai`, `anthropic` or `bedrock` |
| `--model` | provider default | Model name |
| `--config` | `config.yaml` | Configuration file |

You need at least one `audit_*.json` report: run an audit first with the `json` output format enabled (it is by default).

## Configuration

Settings are layered: built-in defaults, then the `ai:` section of `config.yaml`, then environment variables, then CLI flags.

```yaml
ai:
  provider: anthropic        # openai | anthropic | bedrock
  model: ""                  # blank = provider default
  api_key: ""                # prefer environment variables
  temperature: 0.1
  max_tokens: 4096
  business_context: ""       # e.g. "500-person healthcare company, HIPAA required"
  base_url: ""               # OpenAI-compatible endpoint (openai provider only)
  aws_region: us-east-1      # bedrock
  aws_profile: ""            # bedrock; blank = default credential chain
```

| Environment variable | Setting |
|----------------------|---------|
| `GWS_AI_PROVIDER`, `GWS_AI_MODEL` | provider, model |
| `GWS_AI_API_KEY` | API key for the selected provider |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | Used when no key is set elsewhere, matching the selected provider |
| `GWS_AI_TEMPERATURE`, `GWS_AI_MAX_TOKENS` | sampling temperature, response length |
| `GWS_AI_BUSINESS_CONTEXT` | business context |
| `GWS_AI_BASE_URL` | OpenAI-compatible endpoint |
| `GWS_AI_AWS_REGION`, `GWS_AI_AWS_PROFILE` | Bedrock region and named profile |

Keep API keys out of `config.yaml` if the file is committed or shared; use the environment variables.

Default models when `model` is blank: `gpt-4o` (OpenAI), `claude-sonnet-4-20250514` (Anthropic), `anthropic.claude-sonnet-4-20250514-v1:0` (Bedrock). Bedrock uses your normal AWS credential chain (or `aws_profile`) and needs model access enabled for that model in the chosen region.

**`business_context`** is added to the system prompt. A sentence about your size, industry and obligations ("HIPAA", "we share files with external law firms by design") makes prioritization and remediation advice noticeably more relevant. It is sent to the provider with every request.

## Slash commands

Type `/help` in the REPL for the list.

| Command | What it does |
|---------|--------------|
| `/critical` | Critical failures with remediation |
| `/summary` | Executive summary of the report |
| `/remediate [section]` | Remediation plan grouped by security theme, optionally for one section |
| `/compare` | Compare with the previous report: new failures, resolved issues, pass-rate change |
| `/trends` | Trends across all reports: pass rate over time, persistent failures |
| `/inventory [check_id]` | Query inventory data (stale devices, OAuth grants, app passwords, ...) |
| `/search <keyword>` | Search findings |
| `/reports` | List available reports |
| `/report <file>` | Switch to another report |
| `/export md` \| `/export csv` | Save the conversation as Markdown (`analyst_<timestamp>.md`) or the findings as CSV (`findings_<timestamp>.csv`) in the reports directory |
| `/reset` | Clear the conversation history |
| `/quit`, `/exit` | Leave |

Anything not starting with `/` is a question. Answers stream as they are generated.

## Tools

The model decides which tools to call; you do not invoke them directly. All of them only read report files.

| Tool | Purpose |
|------|---------|
| `get_audit_summary` | Totals, pass/fail counts and pass rate for the current report |
| `search_findings` | Filter findings by status, source, section, level or check id |
| `get_check_details` | Everything about one check: actual/expected values, remediation, per-OU detail |
| `get_compliance_by_framework` | Statistics per framework (CIS, CISA, GOOGLE, OTHER) |
| `get_compliance_by_section` | Statistics per section (Gmail, Drive, ...) |
| `get_remediation_plan` | Failing checks in priority order |
| `get_smart_remediation` | Remediation grouped by theme (email authentication, MFA, sharing, ...) with effort estimates |
| `compare_reports` | Differences between two reports |
| `get_trend_analysis` | Trends across several reports |
| `list_available_reports` | Reports in the directory with timestamps and pass rates |
| `query_inventory_data` | Structured data from the inventory checks |
| `get_knowledge_base_url` | Google documentation links from a check's remediation text |
| `export_findings_csv` | Filtered findings as CSV |

A single question may trigger up to 10 rounds of tool calls before the analyst answers.

## Getting good answers

- **Ask for check ids.** "List the failed CRITICAL checks with their ids" gives you something you can verify in the report and the Admin console.
- **Verify before acting.** The analyst explains and prioritizes what is in the report; it can misread or over-generalize like any LLM. Treat remediation steps as a draft: the check's own remediation text and the linked Google documentation are authoritative. It has no access to your tenant, so it cannot confirm that a change worked -- re-run the audit for that.
- **MANUAL is not FAIL.** MANUAL means the auditor could not determine the setting (see [Troubleshooting](Troubleshooting)). If the analyst treats those as failures, say so and it will separate them.
- **Use `/compare` and `/trends` for progress reporting**; they need more than one report in the directory.
- **Use `/reset`** when you switch topic. Long conversations cost more tokens, and every earlier tool result is re-sent with each new question.

## In the dashboard

The **AI Analyst** page in the [Dashboard](Dashboard) uses the report selected in the sidebar and the same configuration. It reads the `ai:` section from `config.yaml` in the directory the dashboard was started from, plus the environment variables above. The conversation lives in the dashboard process, so everyone connected to the same dashboard instance shares it.

## Troubleshooting

| Symptom | Cause |
|---------|-------|
| `AI analyst dependencies are not installed` | Install an AI extra (see above) |
| Authentication error from the provider | No key found for the *selected* provider. `--provider anthropic` needs `ANTHROPIC_API_KEY` (or `GWS_AI_API_KEY`); the default provider is `openai` |
| `No audit reports found` | No `audit_*.json` in `--reports-dir` |
| `/compare` or `/trends` has nothing to show | Only one report in the directory |
| Bedrock access denied | Model access not enabled in that region, or the IAM principal lacks `bedrock:InvokeModel` / `bedrock:InvokeModelWithResponseStream` (answers are streamed) |
