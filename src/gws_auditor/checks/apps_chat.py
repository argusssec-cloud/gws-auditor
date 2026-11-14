# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section 3.1.4: Google Chat checks for GWS Security Auditor.

CIS Google Workspace Benchmark v1.4.1 - Google Chat controls.
"""

from .base import (check, make_pass, make_fail, make_warn, make_manual, make_review, get_ou_values,
                   format_ou_values_readable, field_value, ou_verdict)
from ..constants import (
    EDITIONS_CHAT_EXTERNAL, EDITIONS_CHAT_FILE_SHARING,
)
from ..models import CheckResult, Status


@check(
    check_id="CIS-3.1.4.2.1",
    requires_license=EDITIONS_CHAT_EXTERNAL,
    title="Ensure external chat is restricted to allowed domains",
    level="L1",
    source="CIS",
    section="Google Chat",
    remediation=(
        "Admin console > Apps > Google Workspace > Google Chat > "
        "External chat settings. Restrict external chat to allowlisted domains only. https://knowledge.workspace.google.com/admin/chat/control-external-chat-and-spaces-chat-options"
    ),
)
def check_chat_external_restriction(data: dict) -> CheckResult:
    """External chat should be restricted to allowlisted domains only."""
    _ID = "CIS-3.1.4.2.1"
    _TITLE = "Ensure external chat is restricted to allowed domains"
    _L, _S, _SEC = "L1", "CIS", "Google Chat"
    _REMED = (
        "Admin console > Apps > Google Workspace > Google Chat > "
        "External chat settings. Restrict external chat to allowlisted domains only. https://knowledge.workspace.google.com/admin/chat/control-external-chat-and-spaces-chat-options"
    )

    policies = data.get("policies", {})
    chat = policies.get("chat", {})

    # OU-aware path — check external_chat_restriction (1:1 external chat)
    ou_values = get_ou_values(chat, "external_chat_restriction")
    if ou_values:
        def _judge(entry):
            restriction = field_value(entry, "externalChatRestriction")
            allow_ext = field_value(entry, "allowExternalChat")
            if allow_ext is False or restriction == "TRUSTED_DOMAINS":
                return True, restriction
            if allow_ext is None or restriction is None:
                return None  # the other field could still make the OU compliant
            return False, restriction
        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="do not restrict external chat to allowlisted domains",
            pass_text="restrict external chat to allowlisted domains",
            expected_value="ALLOWLISTED_DOMAINS for all OUs", remediation=_REMED,
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
                "External chat settings. Restrict external chat to allowlisted domains. https://knowledge.workspace.google.com/admin/chat/control-external-chat-and-spaces-chat-options"
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
            "External chat settings. Restrict external chat to allowlisted domains only. https://knowledge.workspace.google.com/admin/chat/control-external-chat-and-spaces-chat-options"
        ),
    )


@check(
    check_id="CIS-3.1.4.4.1",
    title="Ensure Chat app installation is disabled",
    level="L1",
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
    _L, _S, _SEC = "L1", "CIS", "Google Chat"
    _REMED = (
        "Admin console > Apps > Google Workspace > Google Chat > "
        "Chat apps. Disable 'Allow users to install Chat apps'. https://knowledge.workspace.google.com/admin/chat/set-up-app-authorization-for-chat"
    )

    policies = data.get("policies", {})
    chat = policies.get("chat", {})

    # OU-aware path
    ou_values = get_ou_values(chat, "chat_apps_access")
    if ou_values:
        def _judge(entry):
            val = field_value(entry, "enableApps")
            if val is None:
                return None  # edition-dependent default, not injected: unknown
            return val is False
        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have Chat app installation enabled",
            pass_text="have Chat app installation disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    apps = chat.get("apps", {})
    installation_enabled = apps.get("chat_apps_enabled", None)

    if installation_enabled is False:
        return make_pass(
            check_id="CIS-3.1.4.4.1",
            title="Ensure Chat app installation is disabled",
            level="L1", source="CIS", section="Google Chat",
            details="Chat app installation is disabled.",
            actual_value=installation_enabled,
            expected_value="Disabled for all OUs",
        )

    if installation_enabled is None:
        return make_review(
            check_id="CIS-3.1.4.4.1",
            title="Ensure Chat app installation is disabled",
            level="L1", source="CIS", section="Google Chat",
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
        level="L1", source="CIS", section="Google Chat",
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
    level="L1",
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
    _L, _S, _SEC = "L1", "CIS", "Google Chat"
    _REMED = (
        "Admin console > Apps > Google Workspace > Google Chat > "
        "Chat apps. Disable 'Allow users to add incoming webhooks'. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
    )

    policies = data.get("policies", {})
    chat = policies.get("chat", {})

    # OU-aware path
    ou_values = get_ou_values(chat, "chat_apps_access")
    if ou_values:
        def _judge(entry):
            val = field_value(entry, "enableWebhooks")
            if val is None:
                return None  # edition-dependent default, not injected: unknown
            return val is False
        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have incoming webhooks enabled",
            pass_text="have incoming webhooks disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    apps = chat.get("apps", {})
    webhooks_enabled = apps.get("incoming_webhooks_enabled", None)

    if webhooks_enabled is False:
        return make_pass(
            check_id="CIS-3.1.4.4.2",
            title="Ensure incoming webhooks are disabled",
            level="L1", source="CIS", section="Google Chat",
            details="Incoming webhooks are disabled.",
            actual_value=webhooks_enabled,
            expected_value="Disabled for all OUs",
        )

    if webhooks_enabled is None:
        return make_review(
            check_id="CIS-3.1.4.4.2",
            title="Ensure incoming webhooks are disabled",
            level="L1", source="CIS", section="Google Chat",
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
        level="L1", source="CIS", section="Google Chat",
        details="Incoming webhooks are enabled, allowing external data injection into Chat spaces.",
        actual_value=webhooks_enabled,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Google Chat > "
            "Chat apps. Disable 'Allow users to add incoming webhooks'. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
        ),
    )


# ---------------------------------------------------------------------------
# CIS 3.1.4.1.2 / 3.1.4.3.1 (added with the v1.4.1 alignment)
# ---------------------------------------------------------------------------

_CHAT_INT_FS_ID = "CIS-3.1.4.1.2"
_CHAT_INT_FS_TITLE = "Ensure internal file sharing in Google Chat is disabled"
_CHAT_INT_FS_REMED = (
    "Admin console > Apps > Google Workspace > Google Chat > Chat File Sharing. Set 'Internal "
    "filesharing' to 'No files'. https://knowledge.workspace.google.com/admin/chat/control-file-sharing-in-chat"
)


@check(
    check_id=_CHAT_INT_FS_ID,
    requires_license=EDITIONS_CHAT_FILE_SHARING,
    title=_CHAT_INT_FS_TITLE,
    level="L2",
    source="CIS",
    section="Google Chat",
    remediation=_CHAT_INT_FS_REMED,
)
def check_chat_internal_file_sharing(data: dict) -> CheckResult:
    """CIS 3.1.4.1.2: ``chat.chat_file_sharing.internalFileSharing`` must be NO_FILES in every OU."""
    common = dict(check_id=_CHAT_INT_FS_ID, title=_CHAT_INT_FS_TITLE, level="L2", source="CIS", section="Google Chat")
    chat = data.get("policies", {}).get("chat", {})
    ou_values = get_ou_values(chat, "chat_file_sharing")
    if not ou_values:
        return make_review(
            **common, remediation=_CHAT_INT_FS_REMED,
            details="'chat.chat_file_sharing' was not returned by the Cloud Identity Policy API; verify in the Admin console.",
        )

    def judge(entry: dict):
        value = field_value(entry, "internalFileSharing")
        return None if value is None else (value == "NO_FILES", value)

    return ou_verdict(
        ou_values, judge, **common,
        fail_text="allow files to be shared internally in Chat",
        pass_text="block internal file sharing in Chat",
        expected_value="NO_FILES for all OUs", remediation=_CHAT_INT_FS_REMED,
    )


_CHAT_EXT_SP_ID = "CIS-3.1.4.3.1"
_CHAT_EXT_SP_TITLE = "Ensure external spaces in Google Chat are restricted to allowlisted domains"
_CHAT_EXT_SP_REMED = (
    "Admin console > Apps > Google Workspace > Google Chat > External Spaces. With 'Allow users to "
    "create and join spaces with people outside their organization' on, check 'Only allow users to add "
    "people from allowlisted domains' (or turn external spaces off). "
    "https://knowledge.workspace.google.com/admin/chat/control-external-chat-and-spaces-chat-options"
)


@check(
    check_id=_CHAT_EXT_SP_ID,
    requires_license=EDITIONS_CHAT_EXTERNAL,
    title=_CHAT_EXT_SP_TITLE,
    level="L1",
    source="CIS",
    section="Google Chat",
    remediation=_CHAT_EXT_SP_REMED,
)
def check_chat_external_spaces(data: dict) -> CheckResult:
    """CIS 3.1.4.3.1: external spaces limited to allowlisted domains.

    ``chat.chat_external_spaces``: ``enabled`` (external spaces allowed) and ``domainAllowlistMode``
    (``ALL_DOMAINS`` seen live = anyone outside the organisation; any other member = allowlisted
    domains only). External spaces switched off is stricter than the benchmark asks and passes.
    """
    common = dict(check_id=_CHAT_EXT_SP_ID, title=_CHAT_EXT_SP_TITLE, level="L1", source="CIS", section="Google Chat")
    chat = data.get("policies", {}).get("chat", {})
    ou_values = get_ou_values(chat, "chat_external_spaces")
    if not ou_values:
        return make_review(
            **common, remediation=_CHAT_EXT_SP_REMED,
            details="'chat.chat_external_spaces' was not returned by the Cloud Identity Policy API; verify in the Admin console.",
        )

    def judge(entry: dict):
        enabled = field_value(entry, "enabled")
        mode = field_value(entry, "domainAllowlistMode")
        if enabled is False:
            return True, "external spaces off"
        if enabled is None or mode is None:
            return None
        return str(mode).upper() != "ALL_DOMAINS", mode

    return ou_verdict(
        ou_values, judge, **common,
        fail_text="let users create or join external spaces with people from any domain",
        pass_text="restrict external spaces to allowlisted domains (or disable them)",
        expected_value="External spaces off, or allowlisted domains only", remediation=_CHAT_EXT_SP_REMED,
    )
