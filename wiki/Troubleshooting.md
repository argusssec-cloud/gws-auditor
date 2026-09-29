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

## Check Results

**A check reports MANUAL instead of PASS or FAIL**
The auditor does not guess. MANUAL means one of:

- *No Google API exposes the setting* (for example Google Forms response settings, partner TLS rules, Security Sandbox). Verify it in the Admin console using the remediation path shown.
- *The setting is only visible through the admin audit log* (Gemini access, Drive add-ons, multi-party approval, access approvals, external recipient warnings, Context-Aware Access enablement). The auditor reads the most recent change event; if the setting has not been changed inside the log window there is no event to read. Changing and re-saving the setting once makes it visible to future audits.
- *The API returns the policy but not its state* (comprehensive mail storage returns only a rule id; Advanced Protection exposes whether users may enroll, not who has).
- *Collection is opt-in and was not enabled* (**ADD-51** per-mailbox forwarding -- see [Configuration](Configuration)).

**A check reports ERROR with "was not collected"**
The data the check needs is missing. After upgrading, this is normal when re-scoring an old cache with `--cached`: admin roles (ADD-41, ADD-48, ADD-49), MTA-STS records (ADD-50) and licence holders (ADD-52) are only present in caches written by this version or later. Run a live collection. On a live run it means the API call failed -- check the "API errors" section of the report and that the scope is delegated (`admin.directory.rolemanagement.readonly` for roles).

**Two checks contradict each other on user account recovery**
That is deliberate. **CIS-4.1.2.2** requires user self-recovery to be *enabled*; **GWS.COMMONCONTROLS.8.2** (CISA SCuBA) requires it *disabled*. A tenant cannot pass both -- follow the framework your organization is assessed against and exclude the other with `checks.exclude`.

**A result changed after upgrading although nothing changed in the tenant**
Several checks previously read field names the Cloud Identity Policy API does not return, which produced FAIL (and occasionally PASS) regardless of the real setting. They now read the real fields. See the [changelog](https://github.com/argusssec-cloud/gws-auditor/blob/main/CHANGELOG.md) for the list; a changed result reflects the tenant's actual configuration.

**GWS.COMMONCONTROLS.13.1 is MANUAL although every alert rule is on**
The Policy API only returns system-defined alert rules that an admin has modified at least once, so rules still at Google's default cannot be confirmed. The check FAILs definitively when any returned rule is inactive, and otherwise asks you to confirm the rest in Admin console > Rules.

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
