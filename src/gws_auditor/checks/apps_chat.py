# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section 3.1.4: Google Chat checks for GWS Security Auditor.

CIS Google Workspace Benchmark v1.3.0 - Google Chat controls.
"""

from .base import check, make_pass, make_fail, make_warn, make_manual, make_review, get_ou_values, format_ou_values_readable
from ..models import CheckResult, Status


@check(
    check_id="CIS-3.1.4.2.1",
    title="Ensure external chat is restricted to allowed domains",
    level="L1",
    source="CIS",
    section="Google Chat",
    remediation=(
        "Admin console > Apps > Google Workspace > Google Chat > "
        "External chat settings. Restrict external chat to allowlisted domains only. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
    ),
)
def check_chat_external_restriction(data: dict) -> CheckResult:
    """External chat should be restricted to allowlisted domains only."""
    _ID = "CIS-3.1.4.2.1"
    _TITLE = "Ensure external chat is restricted to allowed domains"
    _L, _S, _SEC = "L1", "CIS", "Google Chat"
    _REMED = (
        "Admin console > Apps > Google Workspace > Google Chat > "
        "External chat settings. Restrict external chat to allowlisted domains only. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
    )

    policies = data.get("policies", {})
    chat = policies.get("chat", {})

    # OU-aware path — check external_chat_restriction (1:1 external chat)
    ou_values = get_ou_values(chat, "external_chat_restriction", admin_only=True)
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            restriction = entry["value"].get("externalChatRestriction", "")
            allow_ext = entry["value"].get("allowExternalChat", True)
            if restriction == "TRUSTED_DOMAINS" or allow_ext is False:
                continue  # safe
            unsafe_ous.append({"org_unit": entry["org_unit"], "value": restriction})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) do not restrict external chat to allowlisted domains: {ou_list}",
                actual_value=format_ou_values_readable(unsafe_ous), expected_value="ALLOWLISTED_DOMAINS for all OUs",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) restrict external chat to allowlisted domains.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="ALLOWLISTED_DOMAINS",
        )

    # Fallback: existing mapped value logic
    external = chat.get("external_chat", {})
    restriction = external.get("restriction_mode", "")
    allowed_domains = external.get("allowed_domains", [])

    if restriction == "allowlisted_domains" and len(allowed_domains) > 0:
        return make_pass(
            check_id="CIS-3.1.4.2.1",
            title="Ensure external chat is restricted to allowed domains",
            level="L1", source="CIS", section="Google Chat",
            details=f"External chat is restricted to allowlisted domains ({len(allowed_domains)} configured).",
            actual_value={"mode": restriction, "domain_count": len(allowed_domains)},
            expected_value="allowlisted_domains",
        )

    if restriction == "disabled":
        return make_pass(
            check_id="CIS-3.1.4.2.1",
            title="Ensure external chat is restricted to allowed domains",
            level="L1", source="CIS", section="Google Chat",
            details="External chat is completely disabled.",
            actual_value=restriction,
            expected_value="allowlisted_domains or disabled",
        )

    if not restriction:
        return make_manual(
            check_id="CIS-3.1.4.2.1",
            title="Ensure external chat is restricted to allowed domains",
            level="L1", source="CIS", section="Google Chat",
            details="Could not determine external chat restriction setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Google Chat > "
                "External chat settings. Restrict external chat to allowlisted domains. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
            ),
        )

    return make_fail(
        check_id="CIS-3.1.4.2.1",
        title="Ensure external chat is restricted to allowed domains",
        level="L1", source="CIS", section="Google Chat",
        details=f"External chat restriction is set to '{restriction}' instead of allowlisted domains.",
        actual_value=restriction,
        expected_value="allowlisted_domains or disabled",
        remediation=(
            "Admin console > Apps > Google Workspace > Google Chat > "
            "External chat settings. Restrict external chat to allowlisted domains only. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
        ),
    )


@check(
    check_id="CIS-3.1.4.4.1",
    title="Ensure Chat app installation is disabled",
    level="L2",
    source="CIS",
    section="Google Chat",
    remediation=(
        "Admin console > Apps > Google Workspace > Google Chat > "
        "Chat apps. Disable 'Allow users to install Chat apps'. https://knowledge.workspace.google.com/admin/chat/set-up-app-authorization-for-chat"
    ),
)
def check_chat_app_installation(data: dict) -> CheckResult:
    """Users should not be able to install Chat apps (bots)."""
    _ID = "CIS-3.1.4.4.1"
    _TITLE = "Ensure Chat app installation is disabled"
    _L, _S, _SEC = "L2", "CIS", "Google Chat"
    _REMED = (
        "Admin console > Apps > Google Workspace > Google Chat > "
        "Chat apps. Disable 'Allow users to install Chat apps'. https://knowledge.workspace.google.com/admin/chat/set-up-app-authorization-for-chat"
    )

    policies = data.get("policies", {})
    chat = policies.get("chat", {})

    # OU-aware path
    ou_values = get_ou_values(chat, "chat_apps_access", admin_only=True)
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("enableApps", None)
            if val is not False:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) have Chat app installation enabled: {ou_list}",
                actual_value=format_ou_values_readable(unsafe_ous), expected_value="disabled for all OUs",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have Chat app installation disabled.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="Disabled for all OUs",
        )

    # Fallback: existing mapped value logic
    apps = chat.get("apps", {})
    installation_enabled = apps.get("chat_apps_enabled", None)

    if installation_enabled is False:
        return make_pass(
            check_id="CIS-3.1.4.4.1",
            title="Ensure Chat app installation is disabled",
            level="L2", source="CIS", section="Google Chat",
            details="Chat app installation is disabled.",
            actual_value=installation_enabled,
            expected_value="Disabled for all OUs",
        )

    if installation_enabled is None:
        return make_review(
            check_id="CIS-3.1.4.4.1",
            title="Ensure Chat app installation is disabled",
            level="L2", source="CIS", section="Google Chat",
            details=(
                "Could not determine Chat app installation setting. "
                "Verify manually in Admin console > Apps > Google Workspace > "
                "Google Chat > Chat apps."
            ),
            remediation=(
                "Admin console > Apps > Google Workspace > Google Chat > "
                "Chat apps. Disable 'Allow users to install Chat apps'. https://knowledge.workspace.google.com/admin/chat/set-up-app-authorization-for-chat"
            ),
        )

    return make_fail(
        check_id="CIS-3.1.4.4.1",
        title="Ensure Chat app installation is disabled",
        level="L2", source="CIS", section="Google Chat",
        details="Chat app installation is enabled, allowing users to add third-party bots.",
        actual_value=installation_enabled,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Google Chat > "
            "Chat apps. Disable 'Allow users to install Chat apps'. https://knowledge.workspace.google.com/admin/chat/set-up-app-authorization-for-chat"
        ),
    )


@check(
    check_id="CIS-3.1.4.4.2",
    title="Ensure incoming webhooks are disabled",
    level="L2",
    source="CIS",
    section="Google Chat",
    remediation=(
        "Admin console > Apps > Google Workspace > Google Chat > "
        "Chat apps. Disable 'Allow users to add incoming webhooks'. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
    ),
)
def check_chat_webhooks(data: dict) -> CheckResult:
    """Incoming webhooks in Chat spaces should be disabled."""
    _ID = "CIS-3.1.4.4.2"
    _TITLE = "Ensure incoming webhooks are disabled"
    _L, _S, _SEC = "L2", "CIS", "Google Chat"
    _REMED = (
        "Admin console > Apps > Google Workspace > Google Chat > "
        "Chat apps. Disable 'Allow users to add incoming webhooks'. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
    )

    policies = data.get("policies", {})
    chat = policies.get("chat", {})

    # OU-aware path
    ou_values = get_ou_values(chat, "chat_apps_access", admin_only=True)
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("enableWebhooks", None)
            if val is not False:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) have incoming webhooks enabled: {ou_list}",
                actual_value=format_ou_values_readable(unsafe_ous), expected_value="disabled for all OUs",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have incoming webhooks disabled.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="Disabled for all OUs",
        )

    # Fallback: existing mapped value logic
    apps = chat.get("apps", {})
    webhooks_enabled = apps.get("incoming_webhooks_enabled", None)

    if webhooks_enabled is False:
        return make_pass(
            check_id="CIS-3.1.4.4.2",
            title="Ensure incoming webhooks are disabled",
            level="L2", source="CIS", section="Google Chat",
            details="Incoming webhooks are disabled.",
            actual_value=webhooks_enabled,
            expected_value="Disabled for all OUs",
        )

    if webhooks_enabled is None:
        return make_review(
            check_id="CIS-3.1.4.4.2",
            title="Ensure incoming webhooks are disabled",
            level="L2", source="CIS", section="Google Chat",
            details=(
                "Could not determine incoming webhooks setting. "
                "Verify manually in Admin console > Apps > Google Workspace > "
                "Google Chat > Chat apps."
            ),
            remediation=(
                "Admin console > Apps > Google Workspace > Google Chat > "
                "Chat apps. Disable 'Allow users to add incoming webhooks'. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
            ),
        )

    return make_fail(
        check_id="CIS-3.1.4.4.2",
        title="Ensure incoming webhooks are disabled",
        level="L2", source="CIS", section="Google Chat",
        details="Incoming webhooks are enabled, allowing external data injection into Chat spaces.",
        actual_value=webhooks_enabled,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Google Chat > "
            "Chat apps. Disable 'Allow users to add incoming webhooks'. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
        ),
    )
