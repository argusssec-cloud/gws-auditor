# Configuration

## config.yaml

```yaml
auth:
  method: service_account          # or "oauth"
  credentials_file: credentials.json
  credentials_dir: credentials     # directory for multi-credential profiles
  subject: admin@company.com       # super admin email for impersonation
  customer_id: auto                # "auto" = discover from API, or explicit ID like "C049r06rk"
  # profile: production            # uncomment to use a named profile by default
  profiles:
    production:
      credentials_file: credentials/prod-sa.json
      subject: admin@company.com
    staging:
      credentials_file: credentials/staging-sa.json
      subject: admin@staging.company.com

checks:
  levels: [L1, L2]                 # [L1] for baseline only
  sources: [CIS, OTHER, GOOGLE, CISA]
  sections: all                    # or specific: [Gmail, "Drive and Docs"]
  exclude: []                      # exclude check IDs: [CIS-1.1.3, ADD-04]
  exclude_sections: []             # exclude sections: ["Google Meet"]

output:
  directory: ./reports
  formats: [html, json, csv]

options:
  cache_data: true
  cache_directory: ./cache
  org_units: all                   # or specific OUs: ["/Engineering", "/Sales"]
  max_retries: 5
  rate_limit_qps: 10
  max_log_events: 50000            # cap on audit-log events fetched per log type
  chat_inactive_days: 90           # ADD-29: Chat spaces with no activity
  device_inactive_days: 90         # ADD-30/31/38: devices with no sync
  user_inactive_days: 90           # ADD-42 / ADD-44: accounts with no sign-in
  collect_mailbox_forwarding: false  # ADD-51: opt-in, see below
  mailbox_forwarding_max_users: 500
  trust_rules_file: null           # JSON export of Drive trust rules
  external_sharing_ous: []         # OUs whose external sharing is deliberate

ai:
  provider: anthropic              # openai, anthropic, or bedrock
  model: ""                        # blank = provider default
  api_key: ""                      # prefer env vars: ANTHROPIC_API_KEY, OPENAI_API_KEY
  temperature: 0.1
  max_tokens: 4096

network:
  proxy: null                      # HTTP proxy URL, e.g. http://proxy:8080
  no_proxy: null                   # comma-separated bypass list
  ca_cert: null                    # CA cert for proxy TLS interception
  disable_ssl_verification: false  # insecure, testing only
```

### Opt-in: per-mailbox forwarding (ADD-51)

Mail forwarded to an outside address is a common persistence and exfiltration technique after an account is compromised, and it cannot be seen from tenant-level settings. `collect_mailbox_forwarding: true` makes the auditor read each active user's forwarding addresses and **ADD-51** then fails on any address outside your verified domains.

It is off by default because of what it costs and what it touches:

- The service account impersonates **every active user** (domain-wide delegation, scope `gmail.settings.basic` -- already in the standard scope list, so no re-authorization is needed). Only forwarding settings are read, never message content.
- One Gmail API call per mailbox. `mailbox_forwarding_max_users` (default 500) caps the run; when the cap is hit ADD-51 says so in its details rather than implying full coverage.
- With collection off, ADD-51 reports **MANUAL**, not PASS.

### Checks that need a fresh collection

Several checks read data that older cache files do not contain: admin roles (**ADD-41**, **ADD-48**, **ADD-49**), MTA-STS / TLS-RPT DNS records (**ADD-50**), per-user licence holders (**ADD-52**), Takeout policies (**ADD-09**) and the `enterprise_service_restrictions` / `early_access_apps` policy categories (**GWS.COMMONCONTROLS.16.1 / 16.2**). Re-scoring an old cache with `--cached` reports these as ERROR or MANUAL; run a live collection to evaluate them.

## Multi-Credential Profiles

Store multiple service account keys in the `credentials/` directory:

```
credentials/
  production.json
  staging.json
  client-b.json
```

Define profiles in config.yaml, then switch between them:

```bash
gws-auditor --profile ?              # list available profiles + scanned credentials
gws-auditor --profile production     # use specific profile
gws-auditor --profile staging        # switch tenant
```

## Customer ID Auto-Discovery

Set `customer_id: auto` (the default) and the tool resolves the real customer ID automatically using `customers.get(customerKey="my_customer")`. No need to look it up manually.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `ANTHROPIC_API_KEY` | Anthropic API key for AI analyst |
| `OPENAI_API_KEY` | OpenAI API key for AI analyst |
| `GWS_AI_PROVIDER` | Override AI provider |
| `GWS_AI_MODEL` | Override AI model |

## CLI Overrides

CLI flags take precedence over config.yaml values:

```bash
gws-auditor --credentials other.json --subject other@co.com --customer-id C0xxxx
```
