# Troubleshooting

## Setup Issues

| Error | Cause | Solution |
|-------|-------|----------|
| "Access blocked: admin needs to review Google Auth Library" | Workspace admin restricts OAuth apps | Use `gws-auditor setup --existing-sa-key credentials.json` to bypass OAuth flow |
| "Cannot enable APIs (insufficient project permissions)" | Service account lacks GCP project roles | Grant **Editor**, **Owner**, or **Service Usage Admin** role on the project |
| "Could not find GCP credentials" | No gcloud auth or service account key available | Run `gcloud auth login` first, or use `--existing-sa-key` |

## Authentication Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `403 Not Authorized` | Service account lacks required scopes | Add all scopes in Admin Console > Security > API Controls > Domain-wide Delegation |
| `401 Invalid Credentials` | Invalid or expired credentials file | Re-download JSON key from GCP Console > IAM > Service Accounts > Keys |
| `unauthorized_client` | DWD not configured or wrong subject email | Verify DWD authorization in Admin Console and `subject` is a super admin |
| `Customer not found` | Wrong customer ID | Set `customer_id: auto` in config.yaml for automatic discovery |

## API Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `API not enabled` | Required API not activated | Enable it in GCP Console > APIs & Services > Library |
| `Rate limit exceeded` | Too many API requests | Reduce `rate_limit_qps` in config.yaml (default: 10) |
| `DNS lookup failed` | DNS resolution error | Check network connectivity; DNS checks require outbound port 53 |

## AI Analyst Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `Messages.stream() got unexpected keyword argument 'stream'` | Outdated code | Update to latest version (fixed in v0.1.0) |
| `Could not resolve authentication method` | API key not found | Set env var `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`, then use `--provider anthropic` |
| `No module named 'anthropic'` | SDK not installed | `pip install -e ".[ai-anthropic]"` |

## Dashboard Issues

| Issue | Solution |
|-------|----------|
| `ImportError: dashboard dependencies` | Install with `pip install -e ".[dashboard]"` |
| No reports showing | Ensure JSON reports exist in `--reports-dir` (default: `./reports/`) |
| Port already in use | Use `--port` to specify a different port |
| Black text in dark mode | Update to latest CSS (fixed in v0.1.0) |

## Standalone Executable

| Issue | Solution |
|-------|----------|
| `OSError: Invalid argument` on Windows | Fixed in v0.1.0 -- update to latest build |
| `ImportError: relative import` | Rebuild with latest `gws-auditor.spec` |
| Missing check modules | Rebuild -- spec auto-discovers all check modules |

## Network/Proxy

```yaml
# config.yaml
network:
  proxy: http://proxy.company.com:8080
  no_proxy: localhost,.internal
  ca_cert: /path/to/ca-bundle.pem
  # disable_ssl_verification: true  # last resort only
```

Or via CLI:
```bash
gws-auditor --proxy http://proxy:8080 --ca-cert ca.pem
```
