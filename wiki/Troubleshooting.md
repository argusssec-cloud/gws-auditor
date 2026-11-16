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
| `Domain-wide delegation does not authorize N scope(s)` (yellow, scan continues) | The grant predates a scope added in an upgrade (1.6.0: `cloud-identity.inboundsso.readonly`) | Add the listed scopes to the client ID in Admin Console > Security > API Controls > Domain-wide Delegation; until then the dependent checks report ERROR |
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

- *No Google API or log exposes the setting* (for example Google Forms response settings, recovery information, audit-log retention, Drive trust rules, cloud session control). Verify it in the Admin console using the remediation path shown. These checks are unscored.
- *The setting is only visible through the admin audit log* (Security sandbox, Workspace Studio, TLS compliance rules, Gemini feature access, Skip passwords, secondary-calendar internal sharing, Drive add-ons, multi-party approval, access approvals, Context-Aware Access assignments). The auditor reads the most recent change event in the 180-day admin log; if the setting has not been changed inside that window there is no event to read. Changing and re-saving the setting once makes it visible to future audits.
- *The value is unknown*: the API returned a `*_UNSPECIFIED` enum, or the field is absent and Google documents no default for it. The auditor never turns an unknown value into PASS or FAIL.
- *The evidence is incomplete by nature* (domain-wide delegation grants older than the log retention, Advanced Protection enrollments before the window, OIDC apps no Context-Aware Access evaluation has named yet).
- *Collection is opt-in and was not enabled* (**ADD-51** per-mailbox forwarding -- see [Configuration](Configuration)).

**A result says "Google default, not admin-configured" or "documented Google default"**
The Policy API returned no admin value for that OU, so the auditor judged the `SYSTEM` policy Google returns, or the default Google publishes for a field absent from the response. The verdict is real (that value is in force) but nobody chose it. Saving the setting once in the Admin console turns it into an admin-configured value.

**A check reports NOT_APPLICABLE**
Every edition detected from the licence assignments is outside the edition set Google lists for that feature (the `EDITIONS_*` tuples in `constants.py`, copied from the "Supported editions" line of the Help article the check links to); the details name the editions required. Unknown or mixed editions run the check. If licence detection is wrong for your tenant, set `auth.subscription_type`. The Assured Controls checks need the Assured Controls or Assured Controls Plus add-on SKU.

**The Context-Aware Access inventory was not collected (403 or "not collected")**
The access levels are read from Access Context Manager as the service account itself, not through domain-wide delegation. A 403 means the service account lacks `roles/accesscontextmanager.policyReader` on the Google Cloud organisation, or the Access Context Manager API is not enabled in the auditor's project; discovering the organisation by domain additionally needs `roles/resourcemanager.organizationViewer` (or set `options.cloud_organization_id`). The reason is recorded in the report and the CAA checks fall back to the audit-log inference. `options.collect_access_context: false` skips the read.

**A check reports ERROR with "was not collected"**
The data the check needs is missing. After upgrading, this is normal when re-scoring an old cache with `--cached`: admin roles (ADD-41, ADD-48, ADD-49), MTA-STS records (ADD-50), licence holders (ADD-52), the user-accounts log and per-user usage report (CIS-5.1.1.2, GWS.COMMONCONTROLS.9.1 / 9.2), the Access Context Manager inventory and the newer policy categories are only present in caches written by the version that added them (the list is in [Configuration](Configuration#checks-that-need-a-fresh-collection)). Run a live collection. On a live run it means the API call failed -- check the "API errors" section of the report and that the scope is delegated (`admin.directory.rolemanagement.readonly` for roles).

**Two checks contradict each other on user account recovery**
That is deliberate. **CIS-4.1.2.2** requires user self-recovery to be *enabled*; **GWS.COMMONCONTROLS.8.2** (CISA SCuBA) requires it *disabled*. Likewise **GWS.DRIVEDOCS.2.2** requires that non-members *can* be added to shared-drive files while **CIS-3.1.2.1.2.3** requires that they cannot. A tenant cannot pass both -- follow the framework your organization is assessed against and exclude the other with `checks.exclude`.

**A result changed after upgrading although nothing changed in the tenant**
Several checks previously read field names the Cloud Identity Policy API does not return, which produced FAIL (and occasionally PASS) regardless of the real setting; 1.6.0 additionally changed how unknown values, Google defaults and licence gates are judged. See the [changelog](https://github.com/argusssec-cloud/gws-auditor/blob/main/CHANGELOG.md), which lists the checks whose result moves on the reference tenant; a changed result reflects the tenant's actual configuration or an honest MANUAL where the auditor used to guess.

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
