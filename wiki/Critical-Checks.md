# Critical Checks

24 checks are tagged as **CRITICAL** severity. A failure on any of these represents a severe security risk requiring immediate attention.

## Authentication & Access (15 checks)

| Check ID | Title | Why Critical |
|----------|-------|-------------|
| CIS-1.1.1 | More than 1 Super Admin exists | Single admin = single point of failure. If compromised/locked out, no recovery path. |
| CIS-4.1.1.1 | 2SV enforced for all admins | Admin without MFA = one phished password from full tenant takeover. |
| CIS-4.1.1.2 | Security keys required for admins | Software MFA tokens fall to real-time phishing proxies (evilginx). Hardware keys are phishing-proof. |
| CIS-4.1.1.3 | All users enrolled in 2SV | Any user without MFA is a phishing target for data exfiltration. |
| CIS-4.1.2.1 | Super admin recovery disabled | Recovery via personal email/phone enables social engineering to take over the super admin. |
| CIS-4.2.4.1 | Session duration controlled | No session limit = stolen cookies grant indefinite access (pass-the-cookie). |
| CIS-4.2.1.1 | Third-party app access restricted | Unrestricted = any user can grant external apps corporate data access. |
| CIS-4.2.1.4 | Domain-wide delegation reviewed | DWD = service account can impersonate ANY user. Unreviewed = master key. |
| CIS-4.2.6.1 | Less secure apps disabled | Less secure apps bypass OAuth, accept plain passwords. |
| GWS.COMMONCONTROLS.1.3 | SMS/Voice MFA disabled | SMS MFA is vulnerable to SIM-swap attacks. |
| GWS.COMMONCONTROLS.8.1 | Super admin recovery disabled | Same as CIS-4.1.2.1 (CISA framework). |
| GWS.COMMONCONTROLS.10.4 | Unconfigured 3P apps blocked | Unblocked = new apps auto-gain access bypassing review. |
| ADD-18 | Passkeys enforced | Passkeys eliminate credential phishing entirely. |
| ADD-33 | No dangerous OAuth scope grants | Apps with full Gmail/Drive/Admin scopes can exfiltrate data silently. |
| ADD-36 | No active dangerous OAuth tokens | Active tokens with dangerous scopes = ongoing exfiltration risk. |

## Email Security (5 checks)

| Check ID | Title | Why Critical |
|----------|-------|-------------|
| CIS-3.1.3.2.1 | DKIM enabled for all domains | Without DKIM, email authenticity is unverifiable. Enables domain impersonation. |
| CIS-3.1.3.2.2 | SPF configured for all domains | Without SPF, attackers spoof your domain for phishing campaigns. |
| CIS-3.1.3.2.3 | DMARC configured for all domains | Without DMARC enforcement, spoofed emails still reach inboxes. |
| CIS-3.1.3.5.2 | Auto-forwarding disabled | Attackers set up forwarding to silently exfiltrate all future emails. |
| GWS.GMAIL.4.2 | DMARC policy set to reject | p=none only monitors. p=reject actually blocks spoofed emails. |

## Data Protection (4 checks)

| Check ID | Title | Why Critical |
|----------|-------|-------------|
| CIS-3.1.2.1.1.2 | No public file publishing | Public files get indexed by search engines. One misconfigured doc = data breach. |
| CIS-3.1.3.1.1 | Mail delegation disabled | One compromised account cascades to all delegated mailboxes. |
| GWS.DRIVEDOCS.1.4 | No sharing with non-Google accounts | External sharing outside Google bypasses audit logging and DLP. |
| GWS.DRIVEDOCS.1.5 | No 'anyone with link' sharing | URL in Slack/logs = anyone gets full access. Bypasses all controls. |

## CLI Output

When critical checks fail, the CLI shows a red banner:

```
╭────────────── CRITICAL SECURITY FINDINGS (13) ──────────────╮
│ CIS-4.1.1.1  2SV not enforced for admins                   │
│   Admin accounts without MFA are the highest-risk vector.   │
│ CIS-3.1.3.2.3  DMARC policy is weak                        │
│   Without DMARC, spoofed emails still reach inboxes.        │
╰──────────── These findings require immediate attention ─────╯
```

## CI/CD

```bash
gws-auditor --fail-on-critical
# Exit code 0: no critical failures
# Exit code 1: non-critical failures exist
# Exit code 2: critical failures exist (pipeline should fail)
```

## Customization

Override severity for your environment in config.yaml (future feature):

```yaml
checks:
  critical_overrides:
    ADD-14: MEDIUM      # We don't use Chrome, downgrade Gemini check
    CIS-3.1.7.1: CRITICAL  # Sites is critical for our org
```
