# Quick Start

Get auditing in 5 minutes.

## 1. Install

```bash
pip install -e ".[dev]"
```

## 2. Setup (Automated)

```bash
gws-auditor setup --subject admin@yourdomain.com
```

The wizard will:
- Detect your existing GCP credentials or service account
- Check/enable required APIs
- Generate `config.yaml`
- Guide you through the one manual step (domain-wide delegation)
- Validate connectivity

## 3. Run

```bash
gws-auditor
```

Reports are saved to `./reports/` in HTML, JSON, and CSV formats.

## 4. View Results

```bash
# Interactive dashboard
pip install -e ".[dashboard]"
gws-auditor dashboard
# Open http://127.0.0.1:8050

# AI analyst
pip install -e ".[ai-anthropic]"
export ANTHROPIC_API_KEY="sk-ant-..."
gws-auditor analyst --provider anthropic
```

## Already Have Credentials?

If you have an existing service account key:

```bash
gws-auditor setup --existing-sa-key credentials.json --subject admin@yourdomain.com
```

Or configure manually:

```yaml
# config.yaml
auth:
  method: service_account
  credentials_file: credentials.json
  subject: admin@yourdomain.com
  customer_id: auto
```

```bash
gws-auditor --validate    # test connectivity
gws-auditor               # run audit
```

## Running Without config.yaml

If you don't have a `config.yaml` (e.g. using the standalone binary), you must pass both `--credentials` and `--subject` on the command line:

```bash
gws-auditor --credentials credentials.json --subject admin@yourdomain.com

# Standalone binary
./gws-auditor-linux-amd64 --credentials credentials.json --subject admin@yourdomain.com
```

> **Note:** `--subject` is the super-admin email used for domain-wide delegation. Without it, all API calls will fail with permission/not-found errors.
