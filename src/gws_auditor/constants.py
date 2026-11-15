# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Constants for GWS Security Auditor."""

SCOPES = [
    # Admin SDK – Directory
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.domain.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
    "https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",
    "https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly",
    # Admin SDK – Reports
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.reports.usage.readonly",
    # Groups Settings API
    "https://www.googleapis.com/auth/apps.groups.settings",
    # Gmail API
    "https://www.googleapis.com/auth/gmail.settings.basic",
    # Calendar API
    "https://www.googleapis.com/auth/calendar",
    # Drive API (shared drives + permissions require .readonly)
    "https://www.googleapis.com/auth/drive.readonly",
    # Cloud Identity – Policy API
    "https://www.googleapis.com/auth/cloud-identity.policies.readonly",
    # Cloud Identity – Inbound SSO assignments (GWS.COMMONCONTROLS.6.1: which OUs/groups sign in through an IdP)
    "https://www.googleapis.com/auth/cloud-identity.inboundsso.readonly",
    # Cloud Identity – Devices (endpoint verification: Windows/Mac/Linux)
    "https://www.googleapis.com/auth/cloud-identity.devices.readonly",
    # Chrome Policy API
    "https://www.googleapis.com/auth/chrome.management.policy.readonly",
    # Enterprise License Manager API (subscription/edition detection)
    "https://www.googleapis.com/auth/apps.licensing",
]

# Scope for customer ID auto-discovery. Requested separately so it
# does not break existing domain-wide delegation setups.
CUSTOMER_DISCOVERY_SCOPE = (
    "https://www.googleapis.com/auth/admin.directory.customer.readonly"
)

# Scopes that only work with service-account domain-wide delegation
# (rejected by OAuth consent flow).  Added to SCOPES automatically
# when auth method is ``service_account``.
# Scope the service account uses as itself (no delegation) for Google Cloud APIs such as
# Access Context Manager. Never part of the domain-wide delegation grant.
CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

SERVICE_ACCOUNT_SCOPES = [
    # Chat Admin API – spaces listing + member/owner resolution
    "https://www.googleapis.com/auth/chat.admin.spaces.readonly",
    "https://www.googleapis.com/auth/chat.admin.memberships.readonly",
    # Directory – user security (ASP/App Password listing)
    "https://www.googleapis.com/auth/admin.directory.user.security",
    # Alert Center API
    "https://www.googleapis.com/auth/apps.alerts",
]

DEFAULT_RATE_LIMIT_QPS = 10
DEFAULT_MAX_RETRIES = 5

# GCP APIs that must be enabled for the auditor to function.
REQUIRED_GCP_APIS = [
    "admin.googleapis.com",             # Admin SDK (Directory + Reports)
    "gmail.googleapis.com",             # Gmail API
    "drive.googleapis.com",             # Drive API
    "calendar-json.googleapis.com",     # Calendar API
    "groupssettings.googleapis.com",    # Groups Settings API
    "cloudidentity.googleapis.com",     # Cloud Identity Policy API
    "chromepolicy.googleapis.com",      # Chrome Policy API
    "chat.googleapis.com",              # Chat API
    "alertcenter.googleapis.com",       # Alert Center API
    "licensing.googleapis.com",         # Enterprise License Manager API (license detection)
    # Optional: Context-Aware Access level inventory (Access Context Manager, read as the
    # service account itself; needs roles/accesscontextmanager.policyReader on the organisation).
    "accesscontextmanager.googleapis.com",
    "cloudresourcemanager.googleapis.com",
]

# Cloud Identity Policy API quota: 30 read requests per minute per project.
# We target ~24 req/min (0.4 QPS) to leave headroom for transient bursts and
# concurrent callers sharing the same GCP project quota.
POLICY_API_RATE_LIMIT_QPS = 0.4
DEFAULT_CACHE_DIR = "./cache"
DEFAULT_REPORTS_DIR = "./reports"

# Default lookback windows for activity log collection (days).
# NOTE: Checks that infer current state from admin activity logs
# (e.g. third-party app access reviews) will miss actions taken
# before this window and may return incomplete results.
# The Reports API keeps 180 days; checks that infer a setting from its latest change event
# see nothing older, so the admin log is read over the whole retention.
DEFAULT_ADMIN_LOG_LOOKBACK_DAYS = 180
# Admin events that give a setting's state and are rare: fetched by name over the full
# Reports API retention so a change older than the general window is still seen.
DEFAULT_ADMIN_LOG_EXTENDED_LOOKBACK_DAYS = 180
EXTENDED_ADMIN_LOG_EVENTS = (
    "AUTHORIZE_API_CLIENT_ACCESS",   # domain-wide delegation grant (CIS-4.2.1.4)
    "REMOVE_API_CLIENT_ACCESS",      # domain-wide delegation revocation
    "TOGGLE_CAA_ENABLEMENT",         # Context-Aware Access on/off (GWS.COMMONCONTROLS.2.1, ADD-20)
    "CHANGE_CAA_APP_ASSIGNMENTS",    # access levels assigned to an app (ADD-20)
)
# user_accounts audit log (Advanced Protection enrolment events) and the per-user
# usage report parameters that mirror the Admin console Security report.
DEFAULT_USER_ACCOUNTS_LOG_LOOKBACK_DAYS = 180
USER_USAGE_ACCOUNT_PARAMETERS = (
    "accounts:is_2sv_enrolled",
    "accounts:is_2sv_enforced",
    "accounts:num_security_keys",
    "accounts:num_passkeys_enrolled",
    "accounts:password_strength",
    "accounts:password_length_compliance",
    "accounts:is_less_secure_apps_access_allowed",
    "accounts:num_authorized_apps",
    "accounts:is_suspended",
)
DEFAULT_TOKEN_LOG_LOOKBACK_DAYS = 90
DEFAULT_LOGIN_LOG_LOOKBACK_DAYS = 30
DEFAULT_USAGE_REPORT_LOOKBACK_DAYS = 180

# ---------------------------------------------------------------------------
# Check severity: checks whose failure represents a severe security risk.
# Maps check_id → reason explaining the business impact of failure.
# ---------------------------------------------------------------------------
CRITICAL_CHECKS: dict[str, str] = {
    # Authentication & Access
    "CIS-1.1.1": (
        "A single super admin is a catastrophic single point of failure. "
        "If that account is compromised or locked out, there is no recovery path."
    ),
    "CIS-4.1.1.1": (
        "Admin accounts without MFA are the highest-risk vector for full tenant "
        "compromise. A phished admin password grants unrestricted control."
    ),
    "CIS-4.1.1.2": (
        "Software MFA tokens are vulnerable to real-time phishing proxies "
        "(e.g. evilginx). Hardware security keys provide phishing-resistant auth."
    ),
    "CIS-4.1.1.3": (
        "Any user without MFA is a phishing target. A compromised credential "
        "grants access to Gmail, Drive, Calendar, and all connected services."
    ),
    "CIS-4.1.2.1": (
        "Super admin account recovery via personal email/phone enables social "
        "engineering attacks to take over the most privileged account."
    ),
    "CIS-4.2.4.1": (
        "Without session time limits, stolen session cookies grant indefinite "
        "access. This enables pass-the-cookie attacks to persist undetected."
    ),
    "CIS-4.2.1.1": (
        "Unrestricted third-party app installation allows any user to grant "
        "external applications access to corporate data without review."
    ),
    "CIS-4.2.1.4": (
        "Domain-wide delegation gives a service account the ability to impersonate "
        "any user. An unreviewed delegation is equivalent to a master key."
    ),
    "ADD-58": (  # was CIS-4.2.6.1 until CIS v1.4.1 dropped the recommendation
        "Less secure apps bypass OAuth and accept plain-text passwords. "
        "Enabling them creates a credential interception attack surface."
    ),
    "GWS.COMMONCONTROLS.1.3": (
        "SMS-based MFA is vulnerable to SIM-swap attacks. Allowing SMS/Voice "
        "as an MFA method downgrades the entire authentication posture."
    ),
    "GWS.COMMONCONTROLS.8.1": (
        "Super admin account recovery via personal email/phone enables social "
        "engineering attacks to take over the most privileged account."
    ),
    "GWS.COMMONCONTROLS.10.4": (
        "When unconfigured third-party apps are not blocked, any new app "
        "automatically gains access, bypassing the security review process."
    ),
    "ADD-18": (
        "Passkeys eliminate credential phishing entirely. Not enforcing them "
        "when available leaves the tenant exposed to credential theft."
    ),
    "ADD-33": (
        "OAuth apps with dangerous scopes (full Gmail, Drive, Admin SDK) can "
        "exfiltrate data or modify configuration silently and at scale."
    ),
    "ADD-36": (
        "Active tokens with dangerous scopes represent an ongoing data "
        "exfiltration risk, even without any further authentication."
    ),
    # Email Security
    "CIS-3.1.3.2.1": (
        "Without DKIM, email authenticity cannot be verified. Attackers can "
        "forge emails appearing to come from your domain."
    ),
    "CIS-3.1.3.2.2": (
        "Without SPF, attackers can spoof emails from your domain, enabling "
        "phishing campaigns that target customers, partners, and employees."
    ),
    "CIS-3.1.3.2.3": (
        "Without DMARC, receiving servers have no enforcement policy even if "
        "SPF/DKIM fail. Domain spoofing remains trivially possible."
    ),
    "CIS-3.1.3.5.2": (
        "Attackers who compromise a mailbox immediately set up auto-forwarding "
        "to exfiltrate all current and future emails silently."
    ),
    "GWS.GMAIL.4.2": (
        "A DMARC policy of 'none' only monitors spoofing without blocking it. "
        "Only p=reject actually prevents spoofed emails from being delivered."
    ),
    # Data Protection
    "CIS-3.1.2.1.1.2": (
        "Publicly published files are indexed by search engines and accessible "
        "to anyone worldwide. A single misconfigured document causes a data breach."
    ),
    "CIS-3.1.3.1.1": (
        "Mail delegation allows one user to read and send as another. If enabled "
        "broadly, a single compromised account cascades to all delegated mailboxes."
    ),
    "GWS.DRIVEDOCS.1.4": (
        "Sharing files with non-Google accounts bypasses audit logging and DLP "
        "controls, creating unmonitorable data exfiltration paths."
    ),
    "GWS.DRIVEDOCS.1.5": (
        "'Anyone with the link' sharing bypasses all access controls. Anyone who "
        "obtains the URL via logs, clipboard, or chat messages gets full access."
    ),
}

# Convenience set for quick membership tests
CRITICAL_CHECK_IDS: frozenset[str] = frozenset(CRITICAL_CHECKS.keys())

# ---------------------------------------------------------------------------
# HIGH severity: checks whose failure enables data exfiltration, account
# takeover vectors, or bypasses major security controls.
# ---------------------------------------------------------------------------
HIGH_CHECKS: frozenset[str] = frozenset({
    # Password & session security
    "CIS-4.1.2.2",         # Ensure user account recovery is enabled
    "CIS-4.1.5.1",         # Ensure password policy is enhanced
    "CIS-4.2.5.1",         # Ensure cloud session control is configured
    "CIS-4.1.3.1",         # Ensure Advanced Protection Program is available
    "CIS-4.1.4.1",         # Ensure login challenges are enforced
    "ADD-59",              # Ensure Device Bound Session Credentials (DBSC) are enabled (was CIS-4.2.4.1)
    # Third-party app access
    "CIS-4.2.1.2",         # Ensure third-party apps are reviewed
    "CIS-4.2.1.3",         # Ensure internal app API access is controlled
    "CIS-3.1.9.1.1",       # Ensure Marketplace apps are restricted
    "GWS.COMMONCONTROLS.10.1",  # Ensure app access control policies restrict third-party access
    "GWS.COMMONCONTROLS.10.2",  # Ensure users cannot consent to low-risk app scopes
    "GWS.COMMONCONTROLS.10.3",  # Ensure unconfigured internal apps are not trusted
    # Gmail security controls
    "CIS-3.1.3.4.1.1",    # Ensure encrypted attachment protection is enabled
    "CIS-3.1.3.4.1.2",    # Ensure script attachment protection is enabled
    "CIS-3.1.3.4.1.3",    # Ensure anomalous attachment protection is enabled
    "CIS-3.1.3.4.2.1",    # Ensure shortened URL identification is enabled
    "CIS-3.1.3.4.2.2",    # Ensure linked image scanning is enabled
    "CIS-3.1.3.4.2.3",    # Ensure warning for untrusted links is enabled
    "CIS-3.1.3.4.3.1",    # Ensure domain spoofing protection is enabled
    "CIS-3.1.3.4.3.2",    # Ensure employee name spoofing protection is enabled
    "CIS-3.1.3.4.3.3",    # Ensure inbound domain spoofing protection is enabled
    "CIS-3.1.3.4.3.4",    # Ensure unauthenticated email protection is enabled
    "CIS-3.1.3.4.3.5",    # Ensure Groups inbound spoofing protection is enabled
    "CIS-3.1.3.5.1",      # Ensure POP and IMAP access is disabled
    "CIS-3.1.3.6.1",      # Ensure enhanced pre-delivery message scanning is enabled
    "CIS-3.1.3.6.2",      # Ensure spam filters are not bypassed for internal senders
    "CIS-3.1.3.7.2",      # Ensure secure TLS connection is enforced
    "GWS.GMAIL.4.1",      # Ensure DMARC policy is published for all domains
    "GWS.GMAIL.4.3",      # Ensure DMARC alignment mode is strict
    "GWS.GMAIL.18.1",     # Ensure no domains bypass spam filters
    "GWS.GMAIL.18.2",     # Ensure no domains bypass spam filters and hide warnings
    "GWS.GMAIL.18.3",     # Ensure global spam filter bypass is disabled
    "ADD-02",              # Ensure Security Sandbox is enabled for Gmail
    "ADD-05",              # Ensure MX records point to Google
    "ADD-07",              # Ensure TLS is enforced for partner domains
    # Drive & data protection
    "CIS-3.1.2.1.1.1",    # Ensure users are warned when sharing outside domain
    "CIS-3.1.2.1.1.3",    # Ensure sharing is controlled by domain allowlists
    "CIS-3.1.2.1.1.5",    # Ensure Access Checker limits file access
    "CIS-3.1.2.1.1.6",    # Ensure only internal users can distribute content externally
    "CIS-4.2.3.1",         # Ensure DLP policies are configured for Drive
    "GWS.DRIVEDOCS.1.2",  # Ensure receiving files from non-allowlisted domains is disabled
    "GWS.DRIVEDOCS.1.8",  # Ensure default access for new items is 'private to owner'
    "GWS.COMMONCONTROLS.18.1",  # Ensure DLP rules cover Drive, Calendar, Chat and Gmail for PII
    "ADD-12",              # Ensure DLP rules are configured for Gmail
    "ADD-35",              # Ensure Shared Drives have secure default restrictions
    # External chat & collaboration
    "CIS-3.1.4.2.1",      # Ensure external chat is restricted to allowed domains
    # Groups external access
    "CIS-3.1.6.1",        # Ensure external Groups access is private
    "GWS.GROUPS.1.1",     # Ensure external group access is disabled by default
    "GWS.GROUPS.1.2",     # Ensure external group members are disabled by default
    "GWS.GROUPS.1.3",     # Ensure external posting to groups is disabled
    # Directory exposure
    "CIS-1.2.1.1",        # Ensure directory data is restricted from external access
    # Context-aware access & geo-blocking
    "CIS-4.2.2.1",        # Ensure geo-blocking is configured
    "GWS.COMMONCONTROLS.2.1",  # Ensure context-aware access policies are implemented
    "ADD-54",             # Ensure a device-based Context-Aware Access level is enforced
    # MFA and SSO
    "GWS.COMMONCONTROLS.1.4",  # Ensure MFA enrollment period is configured
    "GWS.COMMONCONTROLS.1.5",  # Ensure 'trust this device' is disabled
    "GWS.COMMONCONTROLS.3.1",  # Ensure SSO verification is enabled for org SSO profile
    "GWS.COMMONCONTROLS.3.2",  # Ensure post-SSO verification is enabled for 3P SSO
    "GWS.COMMONCONTROLS.4.1",  # Ensure users re-authenticate after 12-hour session expiry
    "GWS.COMMONCONTROLS.6.1",  # Ensure admin accounts are cloud-only
    "GWS.COMMONCONTROLS.9.1",  # Ensure privileged accounts are in APP
    "GWS.COMMONCONTROLS.9.2",  # Ensure sensitive users are in APP
    # Active threat indicators
    "ADD-34",              # Ensure no users have active App-Specific Passwords
    # Meet external access
    "GWS.MEET.1.1",       # Ensure external users must ask to join meetings
    "GWS.MEET.2.1",       # Ensure non-GWS tenant meeting access is disabled
    # Audit logging
    "GWS.COMMONCONTROLS.14.1",  # Ensure audit logging is enabled
    "GWS.COMMONCONTROLS.14.2",  # Ensure audit log retention meets minimum requirements
    # Multi-party approval
    "GWS.COMMONCONTROLS.17.1",  # Ensure multi-party approval is enabled
    # Alerts for critical events
    "CIS-6.1",            # Ensure alert for user password change is configured
    "CIS-6.2",            # Ensure alert for government-backed attacks is configured
    "CIS-6.4",            # Ensure alert for admin privilege grant is configured
    "CIS-6.7",            # Ensure alert for leaked password is configured
    # Sites
    "CIS-3.1.7.1",        # Ensure Google Sites creation is disabled
    # Password protection
    "ADD-08",              # Ensure password protection warning is enabled
})

# ---------------------------------------------------------------------------
# LOW severity: informational, best-practice, inventory, or education-
# specific checks with limited direct security impact.
# ---------------------------------------------------------------------------
LOW_CHECKS: frozenset[str] = frozenset({
    # Classroom (education-specific)
    "GWS.CLASSROOM.1.1",  # Ensure class membership is restricted to domain
    "GWS.CLASSROOM.1.2",  # Ensure classes users can join are restricted to domain
    "GWS.CLASSROOM.2.1",  # Ensure Classroom API access is disabled
    "GWS.CLASSROOM.3.1",  # Ensure roster import with Clever is disabled
    "GWS.CLASSROOM.4.1",  # Ensure only teachers can unenroll students
    "GWS.CLASSROOM.5.1",  # Ensure class creation is restricted to verified teachers
    # Review/monitoring checks (manual review items)
    "CIS-5.1.1.1",        # Ensure App Usage Activity Report is reviewed
    "CIS-5.1.1.2",        # Ensure the Security Report is reviewed regularly for anomalies
    # Inventory checks
    "ADD-28",              # Ensure groups have active members
    "ADD-29",              # Ensure Chat spaces have recent activity
    "ADD-30",              # Ensure mobile devices are syncing recently
    "ADD-31",              # Ensure ChromeOS devices are active recently
    "ADD-32",              # Users without 2-Step Verification by OU inventory
    "ADD-38",              # Ensure endpoint verification devices are syncing recently
    "ADD-39",              # Ensure pending devices are approved promptly
    # Gemini / AI features (emerging, low direct risk)
    "GWS.GEMINI.1.1",     # Ensure Gemini app access is restricted to licensed users
    "GWS.GEMINI.2.1",     # Ensure alpha Gemini features are disabled
    "ADD-13",              # Ensure Gemini features in Workspace apps are controlled
    "ADD-14",              # Ensure Gemini in Chrome is disabled
    "ADD-15",              # Ensure Google Workspace Studio access is controlled
    "ADD-16",              # Ensure Apple Intelligence Writing Tools are disabled
    # Assured controls (enterprise edition specific)
    "GWS.ASSUREDCONTROLS.1.1",  # Ensure access approvals are enabled
    "GWS.ASSUREDCONTROLS.1.2",  # Ensure support access is restricted to US personnel
    "GWS.ASSUREDCONTROLS.2.1",  # Ensure multi-region data processing is disabled
    # Meet recording/transcription (low direct security impact)
    "GWS.MEET.5.1",       # Ensure automatic recording is disabled (6.1 before SCuBA v1)
    "GWS.MEET.5.2",       # Ensure automatic transcription is disabled (6.2 before SCuBA v1)
    # Calendar scheduling
    "GWS.CALENDAR.4.1",   # Ensure paid appointment scheduling is disabled
    # Data regions (compliance, not direct security)
    "GWS.COMMONCONTROLS.15.1",  # Ensure data regions are configured
    "GWS.COMMONCONTROLS.15.2",  # Ensure data is processed in the selected storage region
    # Early access apps
    "GWS.COMMONCONTROLS.16.2",  # Ensure early access apps are disabled
    # Conflicting account management
    "GWS.COMMONCONTROLS.7.1",   # Ensure conflicting account management is configured
})

# Maximum number of activity log events to collect per log type.
# Prevents OOM on large tenants.  0 means no limit.
DEFAULT_MAX_LOG_EVENTS = 50000

# Default inactivity thresholds (days)
DEFAULT_CHAT_INACTIVE_DAYS = 90
DEFAULT_DEVICE_INACTIVE_DAYS = 90

# CIS Benchmark version
CIS_BENCHMARK_VERSION = "1.4.1"
CIS_BENCHMARK_TITLE = "CIS Google Workspace Foundations Benchmark"

# ---------------------------------------------------------------------------
# Standards mapping: NIST SP 800-53 Rev. 5 controls and NIST CSF 2.0 subcategories
# per CIS recommendation, copied from the References section of the CIS Google
# Workspace Foundations Benchmark v1.4.1 (every recommendation maps to both).
# Keyed by check id; the @check decorator attaches them to results and metadata.
# ---------------------------------------------------------------------------
NIST_SP800_53_NAME = "NIST SP 800-53 Rev. 5"
NIST_CSF_NAME = "NIST CSF 2.0"
NIST_MAPPINGS: dict[str, dict[str, tuple[str, ...]]] = {
    "CIS-1.1.1": {"sp800_53": ('AC-6(5)',), "csf": ('PR.AA-05',)},
    "CIS-1.1.2": {"sp800_53": ('AC-6(2)',), "csf": ('PR.AA-05',)},
    "CIS-1.2.1.1": {"sp800_53": ('AC-3(11)',), "csf": ('PR.AA-05',)},
    "CIS-3.1.1.1.1": {"sp800_53": ('AC-4',), "csf": ('PR.AA-05',)},
    "CIS-3.1.1.1.2": {"sp800_53": ('AC-6',), "csf": ('PR.AA-05',)},
    "CIS-3.1.1.1.3": {"sp800_53": ('AC-21b',), "csf": ('PR.DS-02',)},
    "CIS-3.1.1.2.1": {"sp800_53": ('AC-3(11)',), "csf": ('PR.AA-05',)},
    "CIS-3.1.1.2.2": {"sp800_53": ('AC-6',), "csf": ('PR.AA-05',)},
    "CIS-3.1.1.3.1": {"sp800_53": ('CM-7b',), "csf": ('PR.PS-01',)},
    "CIS-3.1.2.1.1.1": {"sp800_53": ('AC-21b',), "csf": ('PR.AA-05',)},
    "CIS-3.1.2.1.1.2": {"sp800_53": ('AC-22a',), "csf": ('PR.AA-05',)},
    "CIS-3.1.2.1.1.3": {"sp800_53": ('AC-4',), "csf": ('PR.AA-05',)},
    "CIS-3.1.2.1.1.4": {"sp800_53": ('AC-21b',), "csf": ('PR.AA-05',)},
    "CIS-3.1.2.1.1.5": {"sp800_53": ('AC-6',), "csf": ('PR.AA-05',)},
    "CIS-3.1.2.1.1.6": {"sp800_53": ('AC-4',), "csf": ('PR.AA-05',)},
    "CIS-3.1.2.1.2.1": {"sp800_53": ('SI-12',), "csf": ('PR.DS-01',)},
    "CIS-3.1.2.1.2.2": {"sp800_53": ('AC-6(1)',), "csf": ('PR.AA-05',)},
    "CIS-3.1.2.1.2.3": {"sp800_53": ('AC-3',), "csf": ('PR.AA-05',)},
    "CIS-3.1.2.1.2.4": {"sp800_53": ('AC-6',), "csf": ('PR.AA-05',)},
    "CIS-3.1.2.2.1": {"sp800_53": ('AC-20(3)',), "csf": ('PR.DS-01',)},
    "CIS-3.1.2.3.1": {"sp800_53": ('CM-7b',), "csf": ('PR.PS-01',)},
    "CIS-3.1.3.1.1": {"sp800_53": ('AC-3',), "csf": ('PR.AA-05',)},
    "CIS-3.1.3.1.2": {"sp800_53": ('CM-7b',), "csf": ('PR.PS-01',)},
    "CIS-3.1.3.2.1": {"sp800_53": ('SC-8(1)',), "csf": ('PR.DS-02',)},
    "CIS-3.1.3.2.2": {"sp800_53": ('AC-4',), "csf": ('PR.AA-03',)},
    "CIS-3.1.3.2.3": {"sp800_53": ('AC-4(17)',), "csf": ('PR.DS-02',)},
    "CIS-3.1.3.3.1": {"sp800_53": ('SI-4(5)',), "csf": ('DE.AE-06',)},
    "CIS-3.1.3.4.1.1": {"sp800_53": ('SI-3a',), "csf": ('DE.CM-09',)},
    "CIS-3.1.3.4.1.2": {"sp800_53": ('SI-3a',), "csf": ('DE.CM-09',)},
    "CIS-3.1.3.4.1.3": {"sp800_53": ('SI-3a',), "csf": ('DE.CM-09',)},
    "CIS-3.1.3.4.2.1": {"sp800_53": ('SI-8a',), "csf": ('DE.CM-09',)},
    "CIS-3.1.3.4.2.2": {"sp800_53": ('SI-3c',), "csf": ('DE.CM-09',)},
    "CIS-3.1.3.4.2.3": {"sp800_53": ('SI-8a',), "csf": ('DE.CM-09',)},
    "CIS-3.1.3.4.3.1": {"sp800_53": ('SI-8a',), "csf": ('DE.CM-09',)},
    "CIS-3.1.3.4.3.2": {"sp800_53": ('SI-8a',), "csf": ('DE.CM-09',)},
    "CIS-3.1.3.4.3.3": {"sp800_53": ('AC-4',), "csf": ('DE.CM-09',)},
    "CIS-3.1.3.4.3.4": {"sp800_53": ('SI-8a',), "csf": ('DE.CM-09',)},
    "CIS-3.1.3.4.3.5": {"sp800_53": ('AC-4',), "csf": ('DE.CM-09',)},
    "CIS-3.1.3.5.1": {"sp800_53": ('CM-7b',), "csf": ('PR.PS-01',)},
    "CIS-3.1.3.5.2": {"sp800_53": ('SC-7(10)',), "csf": ('PR.DS-02',)},
    "CIS-3.1.3.5.3": {"sp800_53": ('AC-4',), "csf": ('PR.PS-01',)},
    "CIS-3.1.3.5.4": {"sp800_53": ('AC-21b',), "csf": ('PR.DS-02',)},
    "CIS-3.1.3.6.1": {"sp800_53": ('SI-8a',), "csf": ('DE.CM-09',)},
    "CIS-3.1.3.6.2": {"sp800_53": ('SI-8a',), "csf": ('DE.CM-09',)},
    "CIS-3.1.3.7.1": {"sp800_53": ('SI-12',), "csf": ('PR.DS-01',)},
    "CIS-3.1.3.7.2": {"sp800_53": ('SC-8(1)',), "csf": ('PR.DS-02',)},
    "CIS-3.1.4.1.1": {"sp800_53": ('AC-4',), "csf": ('PR.DS-02',)},
    "CIS-3.1.4.1.2": {"sp800_53": ('CM-7b',), "csf": ('PR.PS-01',)},
    "CIS-3.1.4.2.1": {"sp800_53": ('AC-4',), "csf": ('PR.DS-02',)},
    "CIS-3.1.4.3.1": {"sp800_53": ('AC-3',), "csf": ('PR.AA-05',)},
    "CIS-3.1.4.4.1": {"sp800_53": ('CM-11b',), "csf": ('PR.PS-05',)},
    "CIS-3.1.4.4.2": {"sp800_53": ('CM-7b',), "csf": ('PR.PS-01',)},
    "CIS-3.1.6.1": {"sp800_53": ('AC-3',), "csf": ('PR.AA-05',)},
    "CIS-3.1.6.2": {"sp800_53": ('AC-2c',), "csf": ('PR.AA-05',)},
    "CIS-3.1.6.3": {"sp800_53": ('AC-6',), "csf": ('PR.AA-05',)},
    "CIS-3.1.7.1": {"sp800_53": ('CM-7b',), "csf": ('PR.PS-01',)},
    "CIS-3.1.8.1": {"sp800_53": ('CM-7b',), "csf": ('PR.PS-01',)},
    "CIS-3.1.9.1.1": {"sp800_53": ('CM-11b',), "csf": ('PR.PS-05',)},
    "CIS-4.1.1.1": {"sp800_53": ('IA-2(1)',), "csf": ('PR.AA-03',)},
    "CIS-4.1.1.2": {"sp800_53": ('IA-2(6)',), "csf": ('PR.AA-03',)},
    "CIS-4.1.1.3": {"sp800_53": ('IA-2(2)',), "csf": ('PR.AA-03',)},
    "CIS-4.1.2.1": {"sp800_53": ('IA-5d',), "csf": ('PR.AA-01',)},
    "CIS-4.1.2.2": {"sp800_53": ('IA-5(1)',), "csf": ('PR.AA-01',)},
    "CIS-4.1.3.1": {"sp800_53": ('IA-2(6)',), "csf": ('PR.AA-03',)},
    "CIS-4.1.4.1": {"sp800_53": ('IA-10',), "csf": ('PR.AA-03',)},
    "CIS-4.1.5.1": {"sp800_53": ('IA-5(1)',), "csf": ('PR.AA-03',)},
    "CIS-4.2.1.1": {"sp800_53": ('AC-3(12)',), "csf": ('PR.AA-05',)},
    "CIS-4.2.1.2": {"sp800_53": ('AC-3(12)',), "csf": ('PR.AA-05',)},
    "CIS-4.2.1.3": {"sp800_53": ('CM-7b',), "csf": ('PR.PS-01',)},
    "CIS-4.2.1.4": {"sp800_53": ('AC-6(7)',), "csf": ('PR.AA-05',)},
    "CIS-4.2.2.1": {"sp800_53": ('AC-3(13)',), "csf": ('PR.AA-05',)},
    "CIS-4.2.3.1": {"sp800_53": ('AC-4(15)',), "csf": ('DE.CM-09',)},
    "CIS-4.2.4.1": {"sp800_53": ('AC-12',), "csf": ('PR.AA-03',)},
    "CIS-4.2.5.1": {"sp800_53": ('IA-11',), "csf": ('PR.AA-03',)},
    "CIS-4.3.1": {"sp800_53": ('AU-6a',), "csf": ('DE.CM-03',)},
    "CIS-4.3.2": {"sp800_53": ('CM-6d',), "csf": ('DE.CM-09',)},
    "CIS-5.1.1.1": {"sp800_53": ('AC-2(12)',), "csf": ('DE.CM-03',)},
    "CIS-5.1.1.2": {"sp800_53": ('CA-7d',), "csf": ('DE.CM-03',)},
    "CIS-6.1": {"sp800_53": ('SI-4(5)',), "csf": ('DE.AE-06',)},
    "CIS-6.2": {"sp800_53": ('SI-4(5)',), "csf": ('DE.AE-06',)},
    "CIS-6.3": {"sp800_53": ('SI-4(5)',), "csf": ('DE.AE-06',)},
    "CIS-6.4": {"sp800_53": ('AC-2(7)',), "csf": ('DE.AE-06',)},
    "CIS-6.5": {"sp800_53": ('AC-2(12)',), "csf": ('DE.AE-06',)},
    "CIS-6.6": {"sp800_53": ('AC-2(12)',), "csf": ('DE.AE-06',)},
    "CIS-6.7": {"sp800_53": ('SI-4(5)',), "csf": ('DE.AE-06',)},
    "CIS-6.8": {"sp800_53": ('SI-4(5)',), "csf": ('DE.AE-06',)},
}

# NIST SP 800-53 Rev. 5 (FedRAMP High baseline) controls per CISA SCuBA policy, copied from the
# '_NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping_' line of the SCuBA Google Workspace
# baselines v1 (ScubaGoggles 1.1.0, 2026-10-20). SCuBA publishes no CSF mapping.
NIST_MAPPINGS.update({
    "GWS.ASSUREDCONTROLS.1.1": {"sp800_53": ('SC-7(10)(a)',), "csf": ()},
    "GWS.ASSUREDCONTROLS.1.2": {"sp800_53": ('SC-7(10)(a)',), "csf": ()},
    "GWS.ASSUREDCONTROLS.2.1": {"sp800_53": ('SC-7(10)(a)',), "csf": ()},
    "GWS.CALENDAR.1.1": {"sp800_53": ('AC-3', 'SC-7(10)(a)',), "csf": ()},
    "GWS.CALENDAR.1.2": {"sp800_53": ('AC-3', 'SC-7(10)(a)',), "csf": ()},
    "GWS.CALENDAR.2.1": {"sp800_53": ('AT-2b',), "csf": ()},
    "GWS.CALENDAR.3.1": {"sp800_53": ('CM-7',), "csf": ()},
    "GWS.CALENDAR.3.2": {"sp800_53": ('IA-2(1)', 'IA-2(2)',), "csf": ()},
    "GWS.CALENDAR.4.1": {"sp800_53": ('CM-7',), "csf": ()},
    "GWS.CHAT.1.1": {"sp800_53": ('AU-2', 'SC-7(10)',), "csf": ()},
    "GWS.CHAT.1.2": {"sp800_53": ('AU-9',), "csf": ()},
    "GWS.CHAT.2.1": {"sp800_53": ('AC-3', 'SC-7(10)',), "csf": ()},
    "GWS.CHAT.3.1": {"sp800_53": ('AU-2', 'SC-7(10)',), "csf": ()},
    "GWS.CHAT.4.1": {"sp800_53": ('AC-3',), "csf": ()},
    "GWS.CHAT.5.1": {"sp800_53": ('IR-6',), "csf": ()},
    "GWS.CHAT.5.2": {"sp800_53": ('IR-6',), "csf": ()},
    "GWS.CLASSROOM.1.1": {"sp800_53": ('AC-3',), "csf": ()},
    "GWS.CLASSROOM.1.2": {"sp800_53": ('SC-7(10)',), "csf": ()},
    "GWS.CLASSROOM.2.1": {"sp800_53": ('AC-6(10)',), "csf": ()},
    "GWS.CLASSROOM.3.1": {"sp800_53": ('CM-7',), "csf": ()},
    "GWS.CLASSROOM.4.1": {"sp800_53": ('AC-6(10)',), "csf": ()},
    "GWS.CLASSROOM.5.1": {"sp800_53": ('AC-6(5)', 'AC-6(10)',), "csf": ()},
    "GWS.COMMONCONTROLS.1.1": {"sp800_53": ('IA-2(1)', 'IA-2(2)', 'IA-5c', 'IA-5g', 'IA-2(8)',), "csf": ()},
    "GWS.COMMONCONTROLS.1.2": {"sp800_53": ('IA-2(1)', 'IA-2(2)',), "csf": ()},
    "GWS.COMMONCONTROLS.1.3": {"sp800_53": ('CM-7b', 'IA-5c',), "csf": ()},
    "GWS.COMMONCONTROLS.1.4": {"sp800_53": ('IA-2(1)', 'IA-2(2)',), "csf": ()},
    "GWS.COMMONCONTROLS.1.5": {"sp800_53": ('IA-2(1)', 'IA-2(2)',), "csf": ()},
    "GWS.COMMONCONTROLS.2.1": {"sp800_53": ('IA-3',), "csf": ()},
    "GWS.COMMONCONTROLS.3.1": {"sp800_53": ('IA-2(1)', 'IA-2(2)',), "csf": ()},
    "GWS.COMMONCONTROLS.3.2": {"sp800_53": ('IA-2(1)', 'IA-2(2)',), "csf": ()},
    "GWS.COMMONCONTROLS.4.1": {"sp800_53": ('IA-11',), "csf": ()},
    "GWS.COMMONCONTROLS.5.1": {"sp800_53": ('IA-5(1)',), "csf": ()},
    "GWS.COMMONCONTROLS.5.2": {"sp800_53": ('IA-5(1)',), "csf": ()},
    "GWS.COMMONCONTROLS.5.3": {"sp800_53": ('IA-5(1)',), "csf": ()},
    "GWS.COMMONCONTROLS.5.4": {"sp800_53": ('IA-5(1)',), "csf": ()},
    "GWS.COMMONCONTROLS.5.5": {"sp800_53": ('IA-5(1)',), "csf": ()},
    "GWS.COMMONCONTROLS.5.6": {"sp800_53": ('IA-5(1)',), "csf": ()},
    "GWS.COMMONCONTROLS.6.1": {"sp800_53": ('AC-6(5)',), "csf": ()},
    "GWS.COMMONCONTROLS.6.2": {"sp800_53": ('AC-6(5)',), "csf": ()},
    "GWS.COMMONCONTROLS.7.1": {"sp800_53": ('IA-2',), "csf": ()},
    "GWS.COMMONCONTROLS.8.1": {"sp800_53": ('IA-5d', 'IA-5g',), "csf": ()},
    "GWS.COMMONCONTROLS.8.2": {"sp800_53": ('IA-5d', 'IA-5g',), "csf": ()},
    "GWS.COMMONCONTROLS.8.3": {"sp800_53": ('SC-7(10)',), "csf": ()},
    "GWS.COMMONCONTROLS.9.1": {"sp800_53": ('IA-2(1)', 'IA-2(2)', 'IA-5c', 'IA-5d', 'IA-5g', 'SI-3', 'SI-8',), "csf": ()},
    "GWS.COMMONCONTROLS.9.2": {"sp800_53": ('IA-2(1)', 'IA-2(2)', 'IA-5c', 'IA-5d', 'IA-5g', 'SI-3', 'SI-8',), "csf": ()},
    "GWS.COMMONCONTROLS.10.1": {"sp800_53": ('SI-3',), "csf": ()},
    "GWS.COMMONCONTROLS.10.2": {"sp800_53": ('AC-6',), "csf": ()},
    "GWS.COMMONCONTROLS.10.3": {"sp800_53": ('SI-3',), "csf": ()},
    "GWS.COMMONCONTROLS.10.4": {"sp800_53": ('SI-3',), "csf": ()},
    "GWS.COMMONCONTROLS.10.5": {"sp800_53": ('IA-2(1)', 'IA-2(2)',), "csf": ()},
    "GWS.COMMONCONTROLS.11.1": {"sp800_53": ('CM-7',), "csf": ()},
    "GWS.COMMONCONTROLS.12.1": {"sp800_53": ('CM-7', 'SC-7(10)',), "csf": ()},
    "GWS.COMMONCONTROLS.13.1": {"sp800_53": ('SI-4(5)',), "csf": ()},
    "GWS.COMMONCONTROLS.14.1": {"sp800_53": ('SI-4(5)',), "csf": ()},
    "GWS.COMMONCONTROLS.14.2": {"sp800_53": ('AU-11',), "csf": ()},
    "GWS.COMMONCONTROLS.15.1": {"sp800_53": ('SC-7(10)',), "csf": ()},
    "GWS.COMMONCONTROLS.15.2": {"sp800_53": ('SC-7(10)',), "csf": ()},
    "GWS.COMMONCONTROLS.16.1": {"sp800_53": ('CM-7',), "csf": ()},
    "GWS.COMMONCONTROLS.16.2": {"sp800_53": ('CM-7',), "csf": ()},
    "GWS.COMMONCONTROLS.16.3": {"sp800_53": ('AC-3', 'SC-7(10)',), "csf": ()},
    "GWS.COMMONCONTROLS.16.4": {"sp800_53": ('CM-7',), "csf": ()},
    "GWS.COMMONCONTROLS.17.1": {"sp800_53": ('AC-5',), "csf": ()},
    "GWS.COMMONCONTROLS.18.1": {"sp800_53": ('SC-7(10)',), "csf": ()},
    "GWS.COMMONCONTROLS.18.2": {"sp800_53": ('AC-3', 'SC-7(10)',), "csf": ()},
    "GWS.DRIVEDOCS.1.1": {"sp800_53": ('AC-3', 'SC-7(10)',), "csf": ()},
    "GWS.DRIVEDOCS.1.2": {"sp800_53": ('SI-3', 'SI-8',), "csf": ()},
    "GWS.DRIVEDOCS.1.3": {"sp800_53": ('AT-2b',), "csf": ()},
    "GWS.DRIVEDOCS.1.4": {"sp800_53": ('IA-8', 'SC-7(10)',), "csf": ()},
    "GWS.DRIVEDOCS.1.5": {"sp800_53": ('IA-8',), "csf": ()},
    "GWS.DRIVEDOCS.1.6": {"sp800_53": ('AC-3', 'IA-8', 'SC-7(10)',), "csf": ()},
    "GWS.DRIVEDOCS.1.7": {"sp800_53": ('SC-7(10)',), "csf": ()},
    "GWS.DRIVEDOCS.1.8": {"sp800_53": ('AC-6',), "csf": ()},
    "GWS.DRIVEDOCS.1.9": {"sp800_53": ('IA-8', 'SC-7(10)',), "csf": ()},
    "GWS.DRIVEDOCS.1.10": {"sp800_53": ('IA-8', 'SC-7(10)',), "csf": ()},
    "GWS.DRIVEDOCS.1.11": {"sp800_53": ('IA-8', 'SC-7(10)',), "csf": ()},
    "GWS.DRIVEDOCS.2.1": {"sp800_53": ('AC-6',), "csf": ()},
    "GWS.DRIVEDOCS.2.2": {"sp800_53": ('AC-3',), "csf": ()},
    "GWS.DRIVEDOCS.3.1": {"sp800_53": ('AC-3',), "csf": ()},
    "GWS.DRIVEDOCS.4.1": {"sp800_53": ('CM-7',), "csf": ()},
    "GWS.DRIVEDOCS.5.1": {"sp800_53": ('CM-7',), "csf": ()},
    "GWS.DRIVEDOCS.5.2": {"sp800_53": ('CP-9', 'CP-10',), "csf": ()},
    "GWS.GEMINI.1.1": {"sp800_53": ('SC-7(10)(a)',), "csf": ()},
    "GWS.GEMINI.2.1": {"sp800_53": ('SC-7(10)(a)',), "csf": ()},
    "GWS.GEMINI.3.1": {"sp800_53": ('AU-2', 'AU-11',), "csf": ()},
    "GWS.GEMINI.3.2": {"sp800_53": ('AU-2', 'AU-11',), "csf": ()},
    "GWS.GEMINI.4.1": {"sp800_53": ('SC-7(10)a',), "csf": ()},
    "GWS.GMAIL.1.1": {"sp800_53": ('IA-2', 'SC-7(10)',), "csf": ()},
    "GWS.GMAIL.2.1": {"sp800_53": ('SC-8',), "csf": ()},
    "GWS.GMAIL.3.1": {"sp800_53": ('AC-2d',), "csf": ()},
    "GWS.GMAIL.4.1": {"sp800_53": ('SI-8',), "csf": ()},
    "GWS.GMAIL.4.2": {"sp800_53": ('SI-8',), "csf": ()},
    "GWS.GMAIL.4.3": {"sp800_53": ('SI-4(5)',), "csf": ()},
    "GWS.GMAIL.4.4": {"sp800_53": ('SI-4(5)',), "csf": ()},
    "GWS.GMAIL.5.1": {"sp800_53": ('SI-3', 'SI-8',), "csf": ()},
    "GWS.GMAIL.5.2": {"sp800_53": ('SI-3', 'SI-8',), "csf": ()},
    "GWS.GMAIL.5.3": {"sp800_53": ('SI-3', 'SI-8',), "csf": ()},
    "GWS.GMAIL.5.4": {"sp800_53": ('SI-3', 'SI-8',), "csf": ()},
    "GWS.GMAIL.5.5": {"sp800_53": ('SI-3', 'SI-8',), "csf": ()},
    "GWS.GMAIL.6.1": {"sp800_53": ('SI-3', 'SI-8',), "csf": ()},
    "GWS.GMAIL.6.2": {"sp800_53": ('SI-3', 'SI-8',), "csf": ()},
    "GWS.GMAIL.6.3": {"sp800_53": ('SI-4', 'SI-8', 'AT-2b',), "csf": ()},
    "GWS.GMAIL.6.4": {"sp800_53": ('SI-3', 'SI-8',), "csf": ()},
    "GWS.GMAIL.7.1": {"sp800_53": ('SI-8',), "csf": ()},
    "GWS.GMAIL.7.2": {"sp800_53": ('SI-8',), "csf": ()},
    "GWS.GMAIL.7.3": {"sp800_53": ('SI-8',), "csf": ()},
    "GWS.GMAIL.7.4": {"sp800_53": ('SI-8',), "csf": ()},
    "GWS.GMAIL.7.5": {"sp800_53": ('SI-8',), "csf": ()},
    "GWS.GMAIL.7.6": {"sp800_53": ('SI-8',), "csf": ()},
    "GWS.GMAIL.7.7": {"sp800_53": ('SI-8',), "csf": ()},
    "GWS.GMAIL.8.1": {"sp800_53": ('CM-7', 'SI-3', 'SI-8',), "csf": ()},
    "GWS.GMAIL.9.1": {"sp800_53": ('CM-7',), "csf": ()},
    "GWS.GMAIL.10.1": {"sp800_53": ('CM-7',), "csf": ()},
    "GWS.GMAIL.11.1": {"sp800_53": ('AC-4',), "csf": ()},
    "GWS.GMAIL.12.1": {"sp800_53": ('AC-4',), "csf": ()},
    "GWS.GMAIL.13.1": {"sp800_53": ('AT-2b',), "csf": ()},
    "GWS.GMAIL.14.1": {"sp800_53": ('AC-4',), "csf": ()},
    "GWS.GMAIL.15.1": {"sp800_53": ('SI-3', 'SI-8',), "csf": ()},
    "GWS.GMAIL.16.1": {"sp800_53": ('SI-3', 'SI-8',), "csf": ()},
    "GWS.GMAIL.17.1": {"sp800_53": ('SI-12', 'SC-7(10)',), "csf": ()},
    "GWS.GMAIL.18.1": {"sp800_53": ('SI-8',), "csf": ()},
    "GWS.GMAIL.18.2": {"sp800_53": ('SI-8',), "csf": ()},
    "GWS.GMAIL.18.3": {"sp800_53": ('SI-8',), "csf": ()},
    "GWS.GROUPS.1.1": {"sp800_53": ('AC-3',), "csf": ()},
    "GWS.GROUPS.1.2": {"sp800_53": ('CM-7', 'AC-6(10)',), "csf": ()},
    "GWS.GROUPS.1.3": {"sp800_53": ('CM-7', 'AC-6(10)',), "csf": ()},
    "GWS.GROUPS.2.1": {"sp800_53": ('AC-6(10)',), "csf": ()},
    "GWS.GROUPS.3.1": {"sp800_53": ('AC-6',), "csf": ()},
    "GWS.GROUPS.4.1": {"sp800_53": ('CM-7',), "csf": ()},
    "GWS.MEET.1.1": {"sp800_53": ('IA-2', 'IA-8',), "csf": ()},
    "GWS.MEET.2.1": {"sp800_53": ('IA-8', 'SC-7(10)',), "csf": ()},
    "GWS.MEET.3.1": {"sp800_53": ('CM-7',), "csf": ()},
    "GWS.MEET.4.1": {"sp800_53": ('SC-15',), "csf": ()},
    "GWS.MEET.5.1": {"sp800_53": ('CM-7',), "csf": ()},
    "GWS.MEET.5.2": {"sp800_53": ('CM-7',), "csf": ()},
    "GWS.MEET.6.1": {"sp800_53": ('AC-3', 'SC-7(10)',), "csf": ()},
    "GWS.MEET.6.2": {"sp800_53": ('SC-7(10)',), "csf": ()},
    "GWS.MEET.6.3": {"sp800_53": ('AC-3', 'SC-7(10)',), "csf": ()},
    "GWS.SITES.1.1": {"sp800_53": ('CM-7',), "csf": ()},
})

# SCuBA policies tagged 'BOD 25-01 Requirement' in the v1 baselines: the CISA Binding Operational
# Directive 25-01 makes them mandatory for US federal civilian agencies.
BOD_25_01_CHECKS: frozenset[str] = frozenset({
    "GWS.CALENDAR.1.1", "GWS.CALENDAR.1.2", "GWS.CALENDAR.2.1",
    "GWS.CHAT.1.1", "GWS.CHAT.1.2", "GWS.CHAT.2.1",
    "GWS.CHAT.4.1", "GWS.COMMONCONTROLS.1.1", "GWS.COMMONCONTROLS.1.2",
    "GWS.COMMONCONTROLS.1.3", "GWS.COMMONCONTROLS.1.4", "GWS.COMMONCONTROLS.1.5",
    "GWS.COMMONCONTROLS.4.1", "GWS.COMMONCONTROLS.5.1", "GWS.COMMONCONTROLS.5.2",
    "GWS.COMMONCONTROLS.5.4", "GWS.COMMONCONTROLS.5.5", "GWS.COMMONCONTROLS.5.6",
    "GWS.COMMONCONTROLS.6.1", "GWS.COMMONCONTROLS.6.2", "GWS.COMMONCONTROLS.8.1",
    "GWS.COMMONCONTROLS.8.2", "GWS.COMMONCONTROLS.10.1", "GWS.COMMONCONTROLS.10.2",
    "GWS.COMMONCONTROLS.10.3", "GWS.COMMONCONTROLS.10.4", "GWS.COMMONCONTROLS.10.5",
    "GWS.COMMONCONTROLS.11.1", "GWS.COMMONCONTROLS.12.1", "GWS.COMMONCONTROLS.13.1",
    "GWS.COMMONCONTROLS.15.1", "GWS.COMMONCONTROLS.15.2", "GWS.DRIVEDOCS.1.1",
    "GWS.DRIVEDOCS.1.3", "GWS.DRIVEDOCS.1.6", "GWS.DRIVEDOCS.1.8",
    "GWS.DRIVEDOCS.1.9", "GWS.DRIVEDOCS.2.2", "GWS.DRIVEDOCS.3.1",
    "GWS.DRIVEDOCS.5.1", "GWS.GMAIL.3.1", "GWS.GMAIL.4.1",
    "GWS.GMAIL.4.2", "GWS.GMAIL.4.3", "GWS.GMAIL.5.1",
    "GWS.GMAIL.5.2", "GWS.GMAIL.5.3", "GWS.GMAIL.5.5",
    "GWS.GMAIL.6.1", "GWS.GMAIL.6.2", "GWS.GMAIL.6.3",
    "GWS.GMAIL.6.4", "GWS.GMAIL.7.1", "GWS.GMAIL.7.2",
    "GWS.GMAIL.7.3", "GWS.GMAIL.7.4", "GWS.GMAIL.7.5",
    "GWS.GMAIL.7.6", "GWS.GMAIL.7.7", "GWS.GMAIL.8.1",
    "GWS.GMAIL.9.1", "GWS.GMAIL.12.1", "GWS.GMAIL.15.1",
    "GWS.GMAIL.18.1", "GWS.GMAIL.18.2", "GWS.GMAIL.18.3",
    "GWS.GROUPS.1.1", "GWS.GROUPS.4.1", "GWS.MEET.1.1",
    "GWS.MEET.2.1", "GWS.MEET.3.1", "GWS.MEET.4.1",
    "GWS.MEET.5.1", "GWS.MEET.5.2",
})

# OAuth scopes considered dangerous when granted to third-party apps
DANGEROUS_OAUTH_SCOPES = [
    # Gmail
    "https://mail.google.com/",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.insert",
    "https://www.googleapis.com/auth/gmail.metadata",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.settings.basic",
    "https://www.googleapis.com/auth/gmail.settings.sharing",
    # Drive
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/drive.activity",
    "https://www.googleapis.com/auth/drive.activity.readonly",
    "https://www.googleapis.com/auth/drive.admin",
    "https://www.googleapis.com/auth/drive.admin.labels",
    "https://www.googleapis.com/auth/drive.admin.labels.readonly",
    "https://www.googleapis.com/auth/drive.admin.readonly",
    "https://www.googleapis.com/auth/drive.admin.shareddrive",
    "https://www.googleapis.com/auth/drive.admin.shareddrive.readonly",
    "https://www.googleapis.com/auth/drive.apps",
    "https://www.googleapis.com/auth/drive.apps.readonly",
    "https://www.googleapis.com/auth/drive.categories.readonly",
    "https://www.googleapis.com/auth/drive.labels.readonly",
    "https://www.googleapis.com/auth/drive.meet.readonly",
    "https://www.googleapis.com/auth/drive.metadata",
    "https://www.googleapis.com/auth/drive.metadata.readonly",
    "https://www.googleapis.com/auth/drive.photos.readonly",
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/drive.scripts",
    "https://www.googleapis.com/auth/drive.teams",
    # eDiscovery
    "https://www.googleapis.com/auth/ediscovery",
    "https://www.googleapis.com/auth/ediscovery.readonly",
    # Drive (file-scoped)
    "https://www.googleapis.com/auth/drive.file",
    # Admin – Directory (granular)
    "https://www.googleapis.com/auth/admin.directory.user",
    "https://www.googleapis.com/auth/admin.directory.user.alias",
    "https://www.googleapis.com/auth/admin.directory.user.alias.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.security",
    "https://www.googleapis.com/auth/admin.directory.userschema",
    "https://www.googleapis.com/auth/admin.directory.userschema.readonly",
    "https://www.googleapis.com/auth/admin.directory.group",
    "https://www.googleapis.com/auth/admin.directory.group.member",
    "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.directory.customer",
    "https://www.googleapis.com/auth/admin.directory.customer.readonly",
    "https://www.googleapis.com/auth/admin.directory.domain",
    "https://www.googleapis.com/auth/admin.directory.domain.readonly",
    "https://www.googleapis.com/auth/admin.directory.device.chromeos",
    "https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly",
    "https://www.googleapis.com/auth/admin.directory.device.mobile",
    "https://www.googleapis.com/auth/admin.directory.device.mobile.action",
    "https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",
    "https://www.googleapis.com/auth/admin.directory.notifications",
    "https://www.googleapis.com/auth/admin.directory.orgunit",
    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
    "https://www.googleapis.com/auth/admin.directory.resource.calendar",
    "https://www.googleapis.com/auth/admin.directory.resource.calendar.readonly",
    "https://www.googleapis.com/auth/admin.directory.rolemanagement",
    "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
    # Admin – Reports
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.reports.usage.readonly",
    # Cloud Platform
    "https://www.googleapis.com/auth/cloud-platform",
    # Calendar & Contacts
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/contacts",
    # Docs & Spreadsheets
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/spreadsheets.readonly",
    "https://www.googleapis.com/auth/documents",
    "https://www.googleapis.com/auth/documents.readonly",
    # Forms
    "https://www.googleapis.com/auth/forms.body",
    "https://www.googleapis.com/auth/forms.body.readonly",
    "https://www.googleapis.com/auth/forms.currentonly",
    "https://www.googleapis.com/auth/forms.responses.readonly",
    # Presentations
    "https://www.googleapis.com/auth/presentations",
    "https://www.googleapis.com/auth/presentations.readonly",
    # Apps Script
    "https://www.googleapis.com/auth/script.addons.curation",
    "https://www.googleapis.com/auth/script.projects",
    # Sites
    "https://www.googleapis.com/auth/sites",
    "https://www.googleapis.com/auth/sites.readonly",
    # Chat
    "https://www.googleapis.com/auth/chat.delete",
    "https://www.googleapis.com/auth/chat.import",
    "https://www.googleapis.com/auth/chat.messages",
    "https://www.googleapis.com/auth/chat.messages.readonly",
]

# License tiers (ordered by capability)
LICENSE_TIERS = {
    "essentials_starter": 1,
    "enterprise_essentials": 1,
    "enterprise_essentials_plus": 1,
    "frontline_starter": 2,
    "frontline_standard": 2,
    "frontline_plus": 2,
    "business_starter": 3,
    "enterprise_starter": 3,
    "business_standard": 4,
    "business_plus": 5,
    "enterprise_standard": 6,
    "enterprise_plus": 7,
    # Education editions (mapped to approximate GWS equivalents)
    "education": 3,               # Legacy
    "education_fundamentals": 3,
    "education_standard": 6,
    "education_plus": 7,
    "education_teaching_&_learning": 4,
    # Add-ons (level 99 = never auto-satisfied by any base license; detected from their own SKUs)
    "assured_controls": 99,
    "assured_controls_plus": 99,
}

# Explicit edition sets for ``requires_license``. A tuple means "available on exactly these
# editions" (any-of), which the single minimum-tier string cannot express: many Google features
# reach Frontline, Essentials or Education editions that sit below Business Standard in the tier
# order. Each set is Google's "Supported editions for this feature" line, read on 2026-11-10 from
# the article each check links to. Cloud Identity Premium has no Workspace tier key; a tenant that
# holds only Cloud Identity reports no tier and every gated check runs.
_FRONTLINE_STD_PLUS = ("frontline_standard", "frontline_plus")
_ENTERPRISE = ("enterprise_standard", "enterprise_plus")
_EDU_STD_PLUS = ("education_standard", "education_plus")
_EDU_ALL = ("education_fundamentals", "education_standard", "education_plus")
_ESSENTIALS_ALL = ("essentials_starter", "enterprise_essentials", "enterprise_essentials_plus")

# Context-Aware Access, Skip passwords (passkey-only sign-in)
EDITIONS_CAA = _FRONTLINE_STD_PLUS + _ENTERPRISE + _EDU_STD_PLUS + ("enterprise_essentials_plus",)
# Multi-party approval
EDITIONS_MPA = _ENTERPRISE + _EDU_STD_PLUS + ("enterprise_essentials_plus",)
# DLP for Gmail and Chat
EDITIONS_DLP = _FRONTLINE_STD_PLUS + _ENTERPRISE + _EDU_ALL
# DLP for Drive (also Enterprise Essentials Plus)
EDITIONS_DLP_DRIVE = EDITIONS_DLP + ("enterprise_essentials_plus",)
# DLP for Calendar (also Enterprise Essentials; Cloud Identity Premium has no tier key)
EDITIONS_DLP_CALENDAR = EDITIONS_DLP + ("enterprise_essentials",)
# Client-side encryption (Gmail, Drive...)
EDITIONS_CSE = ("frontline_plus", "enterprise_plus") + _EDU_STD_PLUS
# AI classification labels for Drive
EDITIONS_AI_CLASSIFICATION = ("frontline_plus", "enterprise_plus")
# Classification labels in Gmail
EDITIONS_GMAIL_LABELS = (("frontline_starter",) + _FRONTLINE_STD_PLUS + ("business_standard", "business_plus")
                         + _ENTERPRISE + _EDU_STD_PLUS + _ESSENTIALS_ALL)
# Drive trust rules
EDITIONS_TRUST_RULES = ("frontline_plus",) + _ENTERPRISE + _EDU_STD_PLUS + ("enterprise_essentials_plus",)
# Gmail Security sandbox
EDITIONS_SECURITY_SANDBOX = ("frontline_plus", "business_standard", "business_plus") + _ENTERPRISE
# Gemini in Workspace feature access and Workspace Studio
EDITIONS_GEMINI_WORKSPACE = _ENTERPRISE + ("education_plus", "education_teaching_&_learning")
# Google session control (web session length, Google Cloud session)
EDITIONS_SESSION_CONTROL = _FRONTLINE_STD_PLUS + ("business_plus",) + _ENTERPRISE + _EDU_ALL + ("enterprise_essentials_plus",)
# Chat content reporting / moderation
EDITIONS_CHAT_REPORTING = ("frontline_plus", "enterprise_plus") + _EDU_STD_PLUS
# Chat file sharing controls
EDITIONS_CHAT_FILE_SHARING = ("frontline_plus", "business_plus") + _ENTERPRISE + _EDU_STD_PLUS + ("enterprise_essentials_plus",)
# External Chat with allowlisted domains
EDITIONS_CHAT_EXTERNAL = ("business_standard", "business_plus") + _ENTERPRISE + ("enterprise_essentials", "enterprise_essentials_plus")
# Drive general access (link sharing) options
EDITIONS_DRIVE_GENERAL_ACCESS = ("business_standard", "business_plus") + _ENTERPRISE + _EDU_STD_PLUS
# Shared drive default settings (Business Starter has shared drives but no admin defaults)
EDITIONS_SHARED_DRIVE_SETTINGS = (("frontline_plus", "business_standard", "business_plus") + _ENTERPRISE + _EDU_ALL
                                  + _ESSENTIALS_ALL)
# Meet recording controls
EDITIONS_MEET_RECORDING = ("business_standard", "business_plus") + _ENTERPRISE + ("education_plus",) + _ESSENTIALS_ALL
# Meet transcription controls
EDITIONS_MEET_TRANSCRIPTION = ("business_standard", "business_plus") + _ENTERPRISE + ("education_plus",)
# Paid appointment schedules
EDITIONS_PAID_APPOINTMENTS = ("business_standard", "business_plus") + _ENTERPRISE + _EDU_ALL
# Data regions (storage location, customer-wide)
EDITIONS_DATA_REGIONS = (("frontline_starter",) + _FRONTLINE_STD_PLUS + ("business_standard", "business_plus") + _ENTERPRISE
                         + _EDU_STD_PLUS + ("enterprise_essentials_plus",))
# Data processing region
EDITIONS_DATA_PROCESSING_REGION = ("frontline_plus", "enterprise_plus", "enterprise_essentials_plus")
# Assured Controls add-on (either SKU)
EDITIONS_ASSURED_CONTROLS = ("assured_controls", "assured_controls_plus")

# Human-readable license names
LICENSE_TIER_NAMES = {
    "essentials_starter": "Essentials Starter",
    "enterprise_essentials": "Enterprise Essentials",
    "enterprise_essentials_plus": "Enterprise Essentials Plus",
    "frontline_starter": "Frontline Starter",
    "frontline_standard": "Frontline Standard",
    "frontline_plus": "Frontline Plus",
    "business_starter": "Business Starter",
    "enterprise_starter": "Enterprise Starter",
    "business_standard": "Business Standard",
    "business_plus": "Business Plus",
    "enterprise_standard": "Enterprise Standard",
    "enterprise_plus": "Enterprise Plus",
    "education": "Education (Legacy)",
    "education_fundamentals": "Education Fundamentals",
    "education_standard": "Education Standard",
    "education_plus": "Education Plus",
    "education_teaching_&_learning": "Education Teaching & Learning",
    "assured_controls": "Assured Controls add-on",
    "assured_controls_plus": "Assured Controls Plus add-on",
}

# Remediation theme groupings for the AI analyst's smart remediation tool.
# Maps a human-readable theme name to the check IDs that belong to it.
REMEDIATION_THEMES = {
    "Email Authentication (SPF/DKIM/DMARC)": [
        "CIS-3.1.3.2.1", "GWS.GMAIL.2.1", "CIS-3.1.3.2.2", "GWS.GMAIL.3.1", "CIS-3.1.3.2.3",
        "GWS.GMAIL.4.1", "GWS.GMAIL.4.2", "GWS.GMAIL.4.3", "GWS.GMAIL.4.4", "ADD-62",
        "ADD-05", "ADD-06",
        "ADD-50",
    ],
    "Multi-Factor Authentication": [
        "CIS-4.1.1.1", "CIS-4.1.1.2", "CIS-4.1.1.3", "GWS.COMMONCONTROLS.1.2",
        "GWS.COMMONCONTROLS.1.3", "GWS.COMMONCONTROLS.1.4", "GWS.COMMONCONTROLS.1.5",
        "ADD-18", "ADD-32",
        "GWS.COMMONCONTROLS.1.1",
    ],
    "Phishing & Malware Protection": [
        "CIS-3.1.3.4.1.1", "GWS.GMAIL.5.1", "CIS-3.1.3.4.1.2", "GWS.GMAIL.5.2", "CIS-3.1.3.4.1.3", "GWS.GMAIL.5.3",
        "CIS-3.1.3.4.2.1", "GWS.GMAIL.6.1", "CIS-3.1.3.4.2.2", "GWS.GMAIL.6.2", "CIS-3.1.3.4.2.3", "GWS.GMAIL.6.3",
        "CIS-3.1.3.4.3.1", "GWS.GMAIL.7.1", "CIS-3.1.3.4.3.2", "GWS.GMAIL.7.2", "CIS-3.1.3.4.3.3", "GWS.GMAIL.7.3",
        "CIS-3.1.3.4.3.4", "GWS.GMAIL.7.4", "CIS-3.1.3.4.3.5", "GWS.GMAIL.7.5",
        "CIS-3.1.3.6.1", "GWS.GMAIL.15.1", "CIS-3.1.3.6.2",
        "GWS.GMAIL.5.5", "ADD-02", "GWS.GMAIL.16.1", "ADD-08",
        "GWS.GMAIL.5.4", "GWS.GMAIL.6.4", "GWS.GMAIL.7.6", "GWS.GMAIL.7.7",
    ],
    "External Sharing & Data Protection": [
        "ADD-09", "GWS.COMMONCONTROLS.12.1",
        "CIS-3.1.2.1.1.1", "CIS-3.1.2.1.1.2", "CIS-3.1.2.1.1.3", "GWS.DRIVEDOCS.1.1",
        "CIS-3.1.2.1.1.4", "CIS-3.1.2.1.1.5", "CIS-3.1.2.1.1.6",
        "GWS.DRIVEDOCS.1.2", "GWS.DRIVEDOCS.1.3", "GWS.DRIVEDOCS.1.4",
        "GWS.DRIVEDOCS.1.5", "GWS.DRIVEDOCS.1.6", "GWS.DRIVEDOCS.1.7",
        "GWS.DRIVEDOCS.1.8", "GWS.DRIVEDOCS.1.9", "GWS.DRIVEDOCS.5.1", "GWS.DRIVEDOCS.5.2", "ADD-60",
        "ADD-25",
        "GWS.DRIVEDOCS.1.10", "GWS.DRIVEDOCS.1.11",
    ],
    "Data Loss Prevention": [
        "CIS-4.2.3.1", "ADD-12", "ADD-22", "ADD-23",
        "GWS.COMMONCONTROLS.18.1", "GWS.COMMONCONTROLS.18.2",
    ],
    "Third-Party App Access": [
        "CIS-3.1.9.1.1", "GWS.COMMONCONTROLS.11.1",
        "GWS.COMMONCONTROLS.16.1", "GWS.COMMONCONTROLS.16.2", "GWS.COMMONCONTROLS.16.3", "GWS.COMMONCONTROLS.16.4",
        "CIS-4.2.1.1", "CIS-4.2.1.2", "CIS-4.2.1.3", "CIS-4.2.1.4",
        "GWS.COMMONCONTROLS.10.1", "GWS.COMMONCONTROLS.10.2",
        "GWS.COMMONCONTROLS.10.3", "GWS.COMMONCONTROLS.10.4",
        "ADD-57", "GWS.DRIVEDOCS.4.1", "ADD-58", "GWS.COMMONCONTROLS.10.5", "ADD-33", "ADD-36",
    ],
    "Gmail Access Controls": [
        "CIS-3.1.3.1.1", "GWS.GMAIL.1.1", "CIS-3.1.3.1.2", "CIS-3.1.3.5.1", "GWS.GMAIL.9.1",
        "CIS-3.1.3.5.2", "GWS.GMAIL.11.1", "CIS-3.1.3.5.3", "GWS.GMAIL.12.1", "CIS-3.1.3.5.4", "GWS.GMAIL.13.1",
        "CIS-3.1.3.7.1", "GWS.GMAIL.17.1", "CIS-3.1.3.7.2",
        "GWS.GMAIL.8.1", "GWS.GMAIL.10.1", "GWS.GMAIL.14.1",
        "GWS.GMAIL.18.1", "GWS.GMAIL.18.2", "GWS.GMAIL.18.3",
        "ADD-51",
    ],
    "Shared Drives": [
        "CIS-3.1.2.1.2.1", "CIS-3.1.2.1.2.2", "CIS-3.1.2.1.2.3", "CIS-3.1.2.1.2.4",
        "GWS.DRIVEDOCS.2.1", "GWS.DRIVEDOCS.2.2", "GWS.DRIVEDOCS.3.1",
        "ADD-35",
    ],
    "Session & Access Control": [
        "CIS-4.2.2.1", "CIS-4.2.4.1", "CIS-4.2.5.1", "ADD-59",
        "GWS.COMMONCONTROLS.2.1", "GWS.COMMONCONTROLS.4.1",
        "ADD-20",
        "ADD-47",
        "ADD-53", "ADD-54", "ADD-55", "ADD-56",
    ],
    "Calendar Security": [
        "CIS-3.1.1.1.1", "GWS.CALENDAR.1.1", "CIS-3.1.1.1.2", "CIS-3.1.1.1.3", "GWS.CALENDAR.2.1",
        "CIS-3.1.1.2.1", "GWS.CALENDAR.1.2", "CIS-3.1.1.2.2", "CIS-3.1.1.3.1",
        "GWS.CALENDAR.3.1", "GWS.CALENDAR.3.2", "GWS.CALENDAR.4.1",
    ],
    "Chat Security": [
        "CIS-3.1.4.1.2", "CIS-3.1.4.2.1", "GWS.CHAT.4.1", "CIS-3.1.4.3.1", "CIS-3.1.4.4.1", "CIS-3.1.4.4.2",
        "GWS.CHAT.1.1", "GWS.CHAT.1.2", "GWS.CHAT.3.1",
        "GWS.CHAT.5.1", "GWS.CHAT.5.2",
        "GWS.CHAT.2.1", "CIS-3.1.4.1.1", "ADD-45",
    ],
    "Meet Security": [
        "GWS.MEET.1.1", "GWS.MEET.2.1", "GWS.MEET.3.1",
        "GWS.MEET.4.1", "GWS.MEET.5.1", "GWS.MEET.5.2", "GWS.MEET.6.1", "GWS.MEET.6.2", "GWS.MEET.6.3", "ADD-61",
        "ADD-27",
    ],
    "Groups Security": [
        "CIS-3.1.6.1", "CIS-3.1.6.2", "GWS.GROUPS.2.1", "CIS-3.1.6.3", "CIS-3.1.8.1",
        "GWS.GROUPS.1.1", "GWS.GROUPS.1.2", "GWS.GROUPS.1.3",
        "GWS.GROUPS.3.1", "GWS.GROUPS.4.1", "ADD-37",
        "ADD-46",
    ],
    "Account & Directory Security": [
        "CIS-4.3.1", "CIS-4.3.2", "CIS-5.1.1.1", "CIS-5.1.1.2",
        "CIS-1.1.1", "GWS.COMMONCONTROLS.6.2", "CIS-1.1.2", "CIS-1.2.1.1",
        "CIS-4.1.2.1", "CIS-4.1.2.2", "CIS-4.1.3.1", "CIS-4.1.4.1", "CIS-4.1.5.1", "GWS.COMMONCONTROLS.5.4", "GWS.COMMONCONTROLS.5.2",
        "GWS.COMMONCONTROLS.6.1", "GWS.COMMONCONTROLS.7.1",
        "GWS.COMMONCONTROLS.8.1", "GWS.COMMONCONTROLS.8.2", "GWS.COMMONCONTROLS.8.3",
        "GWS.COMMONCONTROLS.9.1", "GWS.COMMONCONTROLS.9.2",
        "ADD-34",
        "GWS.COMMONCONTROLS.5.1", "GWS.COMMONCONTROLS.5.3", "GWS.COMMONCONTROLS.5.5", "GWS.COMMONCONTROLS.5.6", "GWS.COMMONCONTROLS.13.1", "ADD-41", "ADD-42", "ADD-43", "ADD-44", "ADD-48", "ADD-49", "ADD-52",
    ],
    "Gemini & AI Controls": [
        "ADD-13", "ADD-14", "ADD-15", "ADD-16",
        "GWS.GEMINI.1.1", "GWS.GEMINI.2.1", "GWS.GEMINI.3.1", "GWS.GEMINI.3.2", "GWS.GEMINI.4.1",
    ],
    "Encryption & Compliance": [
        "ADD-11", "ADD-26", "ADD-21",
        "GWS.COMMONCONTROLS.15.1", "GWS.COMMONCONTROLS.15.2",
        "GWS.COMMONCONTROLS.17.1",
        "GWS.ASSUREDCONTROLS.1.1", "GWS.ASSUREDCONTROLS.1.2", "GWS.ASSUREDCONTROLS.2.1",
    ],
}

# Effort estimates for remediation: Low = simple toggle, Medium = requires planning,
# High = requires infrastructure/policy changes.  Unmapped checks default to "Medium".
EFFORT_ESTIMATES = {
    # Low: simple admin console toggles
    "CIS-3.1.3.4.1.1": "Low", "CIS-3.1.3.4.1.2": "Low", "CIS-3.1.3.4.1.3": "Low",
    "CIS-3.1.3.4.2.1": "Low", "CIS-3.1.3.4.2.2": "Low", "CIS-3.1.3.4.2.3": "Low",
    "CIS-3.1.3.4.3.1": "Low", "CIS-3.1.3.4.3.2": "Low", "CIS-3.1.3.4.3.3": "Low",
    "CIS-3.1.3.4.3.4": "Low", "CIS-3.1.3.4.3.5": "Low",
    "CIS-3.1.3.6.1": "Low", "CIS-3.1.3.5.4": "Low",
    "CIS-3.1.1.1.3": "Low", "CIS-3.1.1.3.1": "Low",
    "CIS-3.1.4.4.1": "Low", "CIS-3.1.4.4.2": "Low",
    "GWS.CHAT.5.1": "Low", "GWS.CHAT.5.2": "Low",
    "GWS.MEET.3.1": "Low", "GWS.MEET.4.1": "Low",
    "ADD-08": "Low", "ADD-16": "Low",
    # High: DNS changes, infrastructure, or org-wide policy overhauls
    "CIS-3.1.3.2.1": "High", "CIS-3.1.3.2.2": "High", "CIS-3.1.3.2.3": "High",
    "GWS.GMAIL.4.1": "High", "GWS.GMAIL.4.2": "High",
    "CIS-4.1.1.3": "High", "CIS-4.2.2.1": "High",
    "GWS.COMMONCONTROLS.2.1": "High",
    "ADD-54": "High",  # needs Endpoint Verification / device management rolled out first
    "ADD-11": "High", "ADD-26": "High",
    "ADD-18": "High", "ADD-12": "High",
}

# Reverse lookup: check_id → theme name (built at import time)
CHECK_TO_THEME = {}
for _theme, _ids in REMEDIATION_THEMES.items():
    for _cid in _ids:
        CHECK_TO_THEME[_cid] = _theme

OAUTH_SCOPE_RISK_LEVELS = {
    "mail.google.com": "CRITICAL",
    "gmail.modify": "HIGH",
    "gmail.compose": "HIGH",
    "gmail.insert": "HIGH",
    "gmail.metadata": "MEDIUM",
    "gmail.readonly": "MEDIUM",
    "gmail.send": "HIGH",
    "gmail.settings": "HIGH",
    "drive": "HIGH",
    "drive.admin": "CRITICAL",
    "drive.file": "MEDIUM",
    "drive.readonly": "MEDIUM",
    "drive.scripts": "HIGH",
    "ediscovery": "CRITICAL",
    "admin.directory": "CRITICAL",
    "admin.reports": "HIGH",
    "cloud-platform": "CRITICAL",
    "calendar": "MEDIUM",
    "contacts": "MEDIUM",
    "spreadsheets": "MEDIUM",
    "documents": "MEDIUM",
    "forms": "MEDIUM",
    "presentations": "MEDIUM",
    "sites": "MEDIUM",
    "chat.delete": "HIGH",
    "chat.import": "HIGH",
    "chat.messages": "MEDIUM",
    "script.projects": "HIGH",
    "script.addons": "MEDIUM",
}

# Default Google Workspace Admin Console deep link by check section.
# Used when a check has no explicit console_link.
# NOTE: URLs verified live in the Google Admin Console (2026-06).
# The modern console serves per-app settings pages under customer-specific
# /ac/managedsettings/<nodeId> IDs that cannot be hardcoded for a multi-tenant
# tool, so apps without a stable deep link point at the relevant app list
# (one click from the specific app). Gmail and Marketplace retain stable
# /ac/apps/... deep links.
CONSOLE_SECTION_LINKS = {
    "Directory": "https://admin.google.com/ac/users",
    "Gmail": "https://admin.google.com/ac/apps/gmail/usersettings",
    "Calendar": "https://admin.google.com/ac/appslist/core",
    "Drive": "https://admin.google.com/ac/appslist/core",
    "Chat": "https://admin.google.com/ac/appslist/core",
    "Meet": "https://admin.google.com/ac/appslist/core",
    "Groups": "https://admin.google.com/ac/groups",
    "Sites": "https://admin.google.com/ac/appslist/core",
    "Marketplace": "https://admin.google.com/ac/apps/gmail/marketplace/allowlist",
    "Security": "https://admin.google.com/ac/security",
    "Authentication": "https://admin.google.com/ac/security/2sv",
    "Reporting": "https://admin.google.com/ac/reporting/home",
    "Alert Rules": "https://admin.google.com/ac/ac",
    "Gemini": "https://admin.google.com/ac/ai/home",
    "Classroom": "https://admin.google.com/ac/appslist/additional",
    "Inventory": "https://admin.google.com/ac/users",
}
