"""Shared test fixtures for GWS Security Auditor tests."""

import pytest

from tests.factories import make_dns_domain, make_user


@pytest.fixture
def sample_users():
    """Sample user data matching Directory API response format.

    Uses ``make_user()`` to ensure both camelCase and snake_case fields
    are always present and consistent.
    """
    return [
        make_user(
            email="admin1@example.com",
            is_admin=True,
            is_enrolled_in_2sv=True,
            is_enforced_in_2sv=True,
            full_name="Admin One",
            creation_time="2020-01-01T00:00:00Z",
            last_login_time="2024-01-15T10:00:00Z",
        ),
        make_user(
            email="admin2@example.com",
            is_admin=True,
            is_enrolled_in_2sv=True,
            is_enforced_in_2sv=True,
            full_name="Admin Two",
            creation_time="2020-01-01T00:00:00Z",
            last_login_time="2024-01-14T10:00:00Z",
        ),
        make_user(
            email="user1@example.com",
            is_enrolled_in_2sv=True,
            is_enforced_in_2sv=True,
            full_name="User One",
            creation_time="2021-06-01T00:00:00Z",
            last_login_time="2024-01-15T08:00:00Z",
        ),
        make_user(
            email="user2@example.com",
            full_name="User Two",
            creation_time="2022-03-15T00:00:00Z",
            last_login_time="2024-01-10T14:00:00Z",
        ),
    ]


@pytest.fixture
def sample_domains():
    """Sample domain data."""
    return [
        {
            "domainName": "example.com",
            "isPrimary": True,
            "verified": True,
        },
        {
            "domainName": "example.org",
            "isPrimary": False,
            "verified": True,
        },
    ]


@pytest.fixture
def sample_dns_records():
    """Sample DNS check results.

    Uses ``make_dns_domain()`` to ensure both ``exists`` and
    ``record_found`` fields are always present, resolving the key
    mismatch between the DNS client and checks.
    """
    return {
        "example.com": make_dns_domain(
            spf_found=True,
            spf_record="v=spf1 include:_spf.google.com ~all",
            dkim_found=True,
            dkim_record="v=DKIM1; k=rsa; p=MIGfMA0...",
            dmarc_found=True,
            dmarc_record="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
            dmarc_policy="reject",
        ),
        "example.org": make_dns_domain(
            spf_found=False,
            dkim_found=False,
            dmarc_found=False,
            dmarc_policy="none",
            mx_uses_google=False,
        ),
    }


@pytest.fixture
def sample_policies():
    """Sample policy data using correct post-normalization structure.

    This matches what checks actually access after provider
    normalization (``_map_policies_to_check_schema()``).
    Individual tests override specific nested paths as needed.
    """
    return {
        "gmail": {
            "user_settings": {"mail_delegation_enabled": False},
            "end_user_access": {"pop_enabled": False, "imap_enabled": False},
            "routing": {
                "auto_forwarding_enabled": False,
                "per_user_outbound_gateway_enabled": False,
            },
            "safety": {
                "attachments": {
                    "encrypted_attachment_protection": True,
                    "script_attachment_protection": True,
                    "anomalous_attachment_protection": True,
                },
                "links": {
                    "scan_shortened_urls": True,
                    "scan_linked_images": True,
                    "show_warning_for_untrusted_links": True,
                },
                "spoofing": {
                    "domain_spoofing_protection": True,
                    "employee_name_spoofing_protection": True,
                    "inbound_domain_spoofing_protection": True,
                    "unauthenticated_email_protection": True,
                    "groups_spoofing_protection": True,
                },
                "enhanced_predelivery_scanning": True,
            },
            "compliance": {
                "comprehensive_mail_storage": True,
                "comprehensive_mail_storage_enabled": True,
                "tls_required": True,
            },
            "encryption": {"smime_user_upload": None},
            "_ou_policies": [],
        },
        "drive": {
            "sharing_settings": {
                "warn_on_external_sharing": True,
                "warn_for_external_sharing": True,
                "allow_public_publishing": False,
                "allowlisted_domains_enabled": True,
                "warn_on_allowlisted_domain_sharing": True,
                "access_checker_suggestion": "recipients_only",
                "external_distribution_allowed_for": "internal_users_only",
            },
            "shared_drive_settings": {
                "creation_restricted": True,
                "manager_can_override": False,
                "access_restricted_to_members": True,
                "viewer_download_print_copy_disabled": True,
            },
            "features": {
                "desktop_access_enabled": False,
            },
            "_ou_policies": [],
        },
        "calendar": {
            "primary_calendar": {
                "external_sharing": "only_free_busy",
                "internal_sharing": "all_information",
            },
            "secondary_calendar": {
                "external_sharing": "only_free_busy",
                "internal_sharing": "all_information",
            },
            "external_invitation_warning": True,
            "offline_access_enabled": False,
            "_ou_policies": [],
        },
        "chat": {
            "file_sharing": {
                "external_file_sharing_enabled": False,
                "internal_file_sharing_enabled": False,
            },
            "spaces": {"external_spaces_enabled": False},
            "external_chat": {"restriction_mode": "allowlisted_domains"},
            "apps": {
                "chat_apps_enabled": False,
                "incoming_webhooks_enabled": False,
            },
            "_ou_policies": [],
        },
        "meet": {
            "joining_controls": {"knock_to_join_required": True},
            "safety": {"external_users_must_ask_to_join": True},
            "_ou_policies": [],
        },
        "sites": {
            "sites_creation_enabled": False,
            "_ou_policies": [],
        },
        "marketplace": {
            "app_install_policy": "allowlisted_apps_only",
            "restrict_to_approved_apps": True,
            "_ou_policies": [],
        },
        "security": {
            "two_step_verification": {
                "enrollment_enabled": True,
                "enforcement": True,
                "admin_enforcement": True,
                "admin_allowed_methods": "security_key_only",
            },
            "advanced_protection": {"enrollment_available": True},
            "account_recovery": {
                "super_admin_recovery_enabled": False,
                "user_recovery_enabled": True,
            },
            "session_management": {"web_session_duration_hours": 12},
            "password_management": {
                "enforce_strong_password": True,
                "minimum_length": 12,
            },
            "less_secure_apps": {"allowed": False},
            "login_challenges": {"enabled": True},
            "api_access": {"third_party_apps_restricted": True},
            "app_access": {"third_party_api_access_restricted": True},
            "_ou_policies": [],
        },
        "access_control": {
            "third_party_app_access_restricted": True,
            "internal_app_api_controlled": True,
        },
        "directory": {
            "sharing_settings": {
                "external_sharing_restricted": True,
            },
            "_ou_policies": [],
        },
        "groups": {
            "creation_restricted": True,
            "external_groups_disabled": True,
            "_ou_policies": [],
        },
    }


@pytest.fixture
def sample_admin_logs():
    """Sample admin activity log entries."""
    return [
        {
            "id": {"time": "2024-01-15T10:00:00Z"},
            "actor": {"email": "admin1@example.com"},
            "events": [
                {
                    "type": "ALERT_CENTER",
                    "name": "create",
                    "parameters": [
                        {"name": "alert_name", "value": "User password changed"},
                    ],
                }
            ],
        },
    ]


@pytest.fixture
def sample_groups():
    """Sample groups data."""
    return [
        {
            "email": "team@example.com",
            "name": "Team",
            "settings": {
                "whoCanViewGroup": "ALL_MANAGERS_CAN_VIEW",
                "whoCanViewMembership": "ALL_MANAGERS_CAN_VIEW",
                "whoCanPostMessage": "ALL_MEMBERS_CAN_POST",
                "allowExternalMembers": "false",
                "whoCanJoin": "INVITED_CAN_JOIN",
            },
        },
    ]


@pytest.fixture
def sample_login_logs():
    """Sample login activity logs."""
    return [
        {
            "actor": {"email": "admin1@example.com"},
            "id": {"time": "2024-01-15T10:00:00Z"},
            "events": [{"name": "login_success", "type": "login"}],
        },
    ]


@pytest.fixture
def sample_token_logs():
    """Sample OAuth token activity logs."""
    return []


@pytest.fixture
def sample_usage_reports():
    """Sample usage report data."""
    return {
        "usageReports": [
            {
                "date": "2024-01-15",
                "parameters": [
                    {"name": "accounts:num_users", "intValue": "100"},
                ],
            }
        ]
    }


@pytest.fixture
def full_audit_data(
    sample_users,
    sample_domains,
    sample_dns_records,
    sample_policies,
    sample_admin_logs,
    sample_groups,
    sample_login_logs,
    sample_token_logs,
    sample_usage_reports,
):
    """Complete audit data dict combining all fixtures."""
    return {
        "users": sample_users,
        "domains": sample_domains,
        "org_units": [{"name": "Root", "orgUnitPath": "/"}],
        "groups": sample_groups,
        "group_members": {},
        "policies": sample_policies,
        "chrome_policies": {},
        "admin_logs": sample_admin_logs,
        "login_logs": sample_login_logs,
        "token_logs": sample_token_logs,
        "usage_reports": sample_usage_reports,
        "dns_records": sample_dns_records,
        "alert_center_rules": [],
        "calendar_acls": {},
        "chat_spaces": [],
        "mobile_devices": [],
        "chromeos_devices": [],
        "endpoint_devices": [],
        "app_passwords": [],
        "user_tokens": [],
        "shared_drives": [],
        "subscription_info": {},
        "_options": {},
        "api_errors": [],
    }
