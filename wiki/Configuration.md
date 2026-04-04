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
