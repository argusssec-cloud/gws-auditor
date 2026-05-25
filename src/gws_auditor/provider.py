# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Data collection orchestrator for GWS Security Auditor."""

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone

from collections import Counter

from .auth import AuthManager
from .constants import (
    DEFAULT_ADMIN_LOG_LOOKBACK_DAYS,
    DEFAULT_LOGIN_LOG_LOOKBACK_DAYS,
    DEFAULT_MAX_LOG_EVENTS,
    DEFAULT_TOKEN_LOG_LOOKBACK_DAYS,
    LICENSE_TIERS,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Key-format helpers — the Cloud Identity Policy API returns setting value
# field names in snake_case (e.g. ``warn_for_external_sharing``), while
# some downstream mapping code and checks use camelCase.  These helpers
# ensure both formats are present in every setting value dict so that
# lookups work regardless of convention.
# ---------------------------------------------------------------------------

def _to_snake_case(name: str) -> str:
    """Convert camelCase/PascalCase to snake_case."""
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def _to_camel_case(name: str) -> str:
    """Convert snake_case to lowerCamelCase."""
    components = name.split("_")
    return components[0] + "".join(x.title() for x in components[1:])


def _dual_case_keys(d: dict) -> dict:
    """Add both camelCase and snake_case versions of each key *in-place*.

    Returns *d* for convenience.
    """
    extra: dict = {}
    for k, v in d.items():
        snake = _to_snake_case(k)
        camel = _to_camel_case(k)
        if snake != k and snake not in d:
            extra[snake] = v
        if camel != k and camel not in d:
            extra[camel] = v
    if extra:
        d.update(extra)
    return d


class Provider:
    """Orchestrates all API calls and collects raw configuration data."""

    # Ordered list of (data_key, method_name) for resumable collection.
    # calendar_acls is handled separately (depends on users + domains).
    COLLECTION_ENDPOINTS = [
        ("users", "_get_users_and_admins"),
        ("domains", "_get_domains"),
        ("org_units", "_get_org_units"),
        ("groups", "_get_groups_with_settings"),
        ("group_members", "_get_group_members"),
        ("policies", "_get_all_policies"),
        ("chrome_policies", "_get_chrome_policies"),
        ("admin_logs", "_get_admin_activity_logs"),
        ("login_logs", "_get_login_logs"),
        ("token_logs", "_get_token_logs"),
        ("caa_events", "_get_caa_events"),
        ("usage_reports", "_get_usage_reports"),
        ("dns_records", "_get_dns_records"),
        ("alert_center_rules", "_get_alert_center_rules"),
        ("chat_spaces", "_get_chat_spaces"),
        ("mobile_devices", "_get_mobile_devices"),
        ("chromeos_devices", "_get_chromeos_devices"),
        ("endpoint_devices", "_get_endpoint_devices"),
        ("app_passwords", "_get_app_passwords"),
        ("user_tokens", "_get_user_tokens"),
        ("shared_drives", "_get_shared_drives"),
    ]

    def __init__(self, auth_manager: AuthManager, config: dict):
        self.auth = auth_manager
        self.config = config
        self.options = config.get("options", {})
        self.customer_id = config.get("auth", {}).get("customer_id", "my_customer")
        self._api_errors: list[dict] = []
        self._domains_cache: list[dict] | None = None
        self._org_units_cache: list[dict] | None = None

    def collect_all(self) -> dict:
        """Collect all GWS configuration data from APIs."""
        logger.info("Starting data collection...")

        groups = self._get_groups_with_settings()

        data = {
            "users": self._get_users_and_admins(),
            "domains": self._get_domains(),
            "org_units": self._get_org_units(),
            "groups": groups,
            "group_members": self._get_group_members(groups),
            "policies": self._get_all_policies(),
            "chrome_policies": self._get_chrome_policies(),
            "admin_logs": self._get_admin_activity_logs(),
            "login_logs": self._get_login_logs(),
            "token_logs": self._get_token_logs(),
            "caa_events": self._get_caa_events(),
            "usage_reports": self._get_usage_reports(),
            "dns_records": self._get_dns_records(),
            "alert_center_rules": self._get_alert_center_rules(),
            "chat_spaces": self._get_chat_spaces(),
            "mobile_devices": self._get_mobile_devices(),
            "chromeos_devices": self._get_chromeos_devices(),
            "endpoint_devices": self._get_endpoint_devices(),
            "app_passwords": self._get_app_passwords(),
            "user_tokens": self._get_user_tokens(),
            "shared_drives": self._get_shared_drives(),
            "subscription_info": self._get_subscription_info(),
            "drive_sdk_enabled": self._detect_drive_sdk(),
            "calendar_acls": {},
            "api_errors": self._api_errors,
            "collection_timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Resolve any org-unit IDs found in policy data that are missing
        # from the list_org_units() response.
        self._backfill_org_units(data)

        # Fetch calendar ACLs (needs users + domains collected above)
        data["calendar_acls"] = self._get_calendar_acls(data)

        if self.options.get("cache_data", True):
            self._save_cache(data)

        # Normalize raw API data into the format checks expect
        data = normalize_data(data)

        logger.info("Data collection complete. API errors: %d", len(self._api_errors))
        return data

    def _propagate_client_errors(self, client) -> None:
        """Copy errors from an API client instance to Provider's error list.

        API clients (BaseAPIClient subclasses) record non-fatal errors on
        ``client.errors`` but this list is lost when the client goes out of
        scope.  This method copies them to ``self._api_errors`` so they
        appear in the final report.
        """
        if hasattr(client, "errors") and client.errors:
            for err in client.errors:
                self._api_errors.append(err)
                logger.warning("API client error: %s", err)

    def _get_users_and_admins(self) -> list[dict]:
        """Fetch all users with admin role information."""
        try:
            from .api.directory import DirectoryClient
            client = DirectoryClient(self.auth)
            users = client.list_users(self.customer_id)
            self._propagate_client_errors(client)
            logger.info("Collected %d users", len(users))
            return users
        except Exception as e:
            self._record_error("list_users", e)
            return []

    def _get_domains(self) -> list[dict]:
        """Fetch all domains (cached after first call)."""
        if self._domains_cache is not None:
            return self._domains_cache
        try:
            from .api.directory import DirectoryClient
            client = DirectoryClient(self.auth)
            domains = client.list_domains(self.customer_id)
            self._propagate_client_errors(client)
            logger.info("Collected %d domains", len(domains))
            self._domains_cache = domains
            return domains
        except Exception as e:
            self._record_error("list_domains", e)
            return []

    def _get_org_units(self) -> list[dict]:
        """Fetch organizational units (cached after first call)."""
        if self._org_units_cache is not None:
            return self._org_units_cache
        try:
            from .api.directory import DirectoryClient
            client = DirectoryClient(self.auth)
            ous = client.list_org_units(self.customer_id)
            self._propagate_client_errors(client)
            logger.info("Collected %d org units", len(ous))
            self._org_units_cache = ous
            return ous
        except Exception as e:
            self._record_error("list_org_units", e)
            return []

    def _backfill_org_units(self, data: dict) -> None:
        """Fetch org-unit details for any IDs in policy data missing from org_units.

        The Cloud Identity Policy API references org units as
        ``orgUnits/<id>``, but ``list_org_units()`` may not return every
        OU (e.g. if the API call partially failed, or the root OU is
        omitted).  This method scans all collected policy data for
        ``orgUnits/<id>`` references, builds the set of IDs already
        known from ``data["org_units"]``, and fetches any missing ones
        individually via the Directory API ``orgunits.get()`` endpoint.
        """
        org_units = data.get("org_units", [])
        policies = data.get("policies", {})

        # Build set of bare IDs already known
        known_ids: set[str] = set()
        for ou in org_units:
            if not isinstance(ou, dict):
                continue
            ou_id = ou.get("orgUnitId", "")
            if ou_id:
                known_ids.add(ou_id.removeprefix("id:"))

        # Scan policies for orgUnits/<id> references
        missing_ids: set[str] = set()
        for _category, value in policies.items():
            if not isinstance(value, list):
                continue
            for policy in value:
                if not isinstance(policy, dict):
                    continue
                raw_ou = policy.get("orgUnit", "")
                if raw_ou.startswith("orgUnits/"):
                    bare_id = raw_ou.split("/", 1)[1]
                    if bare_id not in known_ids:
                        missing_ids.add(bare_id)

        if not missing_ids:
            return

        logger.info(
            "Backfilling %d org unit(s) referenced in policies but "
            "missing from list_org_units: %s",
            len(missing_ids),
            missing_ids,
        )

        try:
            from .api.directory import DirectoryClient
            client = DirectoryClient(self.auth)

            for bare_id in missing_ids:
                ou = client.get_org_unit(self.customer_id, bare_id)
                if ou and isinstance(ou, dict):
                    org_units.append(ou)
                    logger.info(
                        "Backfilled org unit %s -> %s",
                        bare_id,
                        ou.get("orgUnitPath", ""),
                    )

            self._propagate_client_errors(client)
        except Exception as e:
            logger.warning("Failed to backfill org units: %s", e)

    def _get_groups_with_settings(self) -> list[dict]:
        """Fetch all groups and their settings."""
        try:
            from .api.directory import DirectoryClient
            from .api.groups import GroupsClient

            dir_client = DirectoryClient(self.auth)
            groups_client = GroupsClient(self.auth)

            groups = dir_client.list_groups(self.customer_id)
            self._propagate_client_errors(dir_client)

            # Deduplicate groups by email (Directory API may return dupes)
            seen: set[str] = set()
            unique_groups: list[dict] = []
            for g in groups:
                email = g.get("email", "")
                if email and email not in seen:
                    seen.add(email)
                    unique_groups.append(g)
                elif not email:
                    unique_groups.append(g)
            if len(unique_groups) < len(groups):
                logger.info(
                    "Deduplicated groups: %d → %d",
                    len(groups), len(unique_groups),
                )
            groups = unique_groups

            logger.info("Collected %d groups", len(groups))

            # Batch-fetch settings (reduces N serial calls to ceil(N/100) batch calls)
            emails = [g["email"] for g in groups if g.get("email")]
            settings_map = groups_client.batch_get_group_settings(emails)
            for group in groups:
                group["settings"] = settings_map.get(group.get("email", ""), {})

            self._propagate_client_errors(groups_client)
            return groups
        except Exception as e:
            self._record_error("list_groups_with_settings", e)
            return []

    def _get_all_policies(self) -> dict:
        """Fetch all GWS policies via Cloud Identity Policy API."""
        try:
            from .api.policy import PolicyClient
            client = PolicyClient(self.auth, customer_id=self.customer_id)
            policies = client.get_all_policies()
            self._propagate_client_errors(client)

            # Check if the API returned any data at all
            total = sum(len(v) for v in policies.values() if isinstance(v, list))
            if total == 0 and client.errors:
                logger.warning(
                    "Cloud Identity Policy API returned no data. "
                    "This API may not be enabled in your GCP project, "
                    "or the OAuth token may not include the "
                    "cloud-identity.policies.readonly scope. "
                    "Policy-dependent checks will return MANUAL status."
                )
            logger.info("Collected policies for %d categories (%d total)", len(policies), total)
            return policies
        except Exception as e:
            self._record_error("get_all_policies", e)
            return {}

    def _get_chrome_policies(self) -> dict:
        """Fetch Chrome browser policies via Chrome Policy API."""
        try:
            from .api.chrome_policy import ChromePolicyClient
            client = ChromePolicyClient(self.auth)
            chrome_policies = client.get_chrome_policies(self.customer_id)
            self._propagate_client_errors(client)
            logger.info("Collected Chrome policies: %s", list(chrome_policies.keys()))
            return chrome_policies
        except Exception as e:
            self._record_error("get_chrome_policies", e)
            return {}

    def _get_max_log_events(self) -> int:
        """Return the configured max log events limit."""
        return self.options.get("max_log_events", DEFAULT_MAX_LOG_EVENTS)

    def _get_admin_activity_logs(self) -> list[dict]:
        """Fetch recent admin activity audit logs."""
        try:
            from .api.reports import ReportsClient
            client = ReportsClient(self.auth)
            dt = datetime.now(timezone.utc) - timedelta(days=DEFAULT_ADMIN_LOG_LOOKBACK_DAYS)
            start_time = dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            logs = client.get_admin_activities(
                self.customer_id,
                start_time=start_time,
                max_items=self._get_max_log_events(),
            )
            self._propagate_client_errors(client)
            logger.info("Collected %d admin activity events", len(logs))
            return logs
        except Exception as e:
            self._record_error("get_admin_activities", e)
            return []

    def _get_login_logs(self) -> list[dict]:
        """Fetch recent login activity logs."""
        try:
            from .api.reports import ReportsClient
            client = ReportsClient(self.auth)
            dt = datetime.now(timezone.utc) - timedelta(days=30)
            start_time = dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            logs = client.get_login_activities(
                self.customer_id,
                start_time=start_time,
                max_items=self._get_max_log_events(),
            )
            self._propagate_client_errors(client)
            logger.info("Collected %d login events", len(logs))
            return logs
        except Exception as e:
            self._record_error("get_login_activities", e)
            return []

    def _get_token_logs(self) -> list[dict]:
        """Fetch OAuth token grant activity logs."""
        try:
            from .api.reports import ReportsClient
            client = ReportsClient(self.auth)
            dt = datetime.now(timezone.utc) - timedelta(days=DEFAULT_TOKEN_LOG_LOOKBACK_DAYS)
            start_time = dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            logs = client.get_token_activities(
                self.customer_id,
                start_time=start_time,
                max_items=self._get_max_log_events(),
            )
            self._propagate_client_errors(client)
            logger.info("Collected %d token events", len(logs))
            return logs
        except Exception as e:
            self._record_error("get_token_activities", e)
            return []

    def _get_caa_events(self) -> list[dict]:
        """Fetch Context-Aware Access denial activity logs.

        Reads ``applicationName=context_aware_access`` from the Reports
        API.  The single documented event ``ACCESS_DENY_EVENT`` fires when
        a CAA policy blocks an access attempt — used as positive evidence
        that CAA is actively enforcing.
        """
        try:
            from .api.reports import ReportsClient
            client = ReportsClient(self.auth)
            dt = datetime.now(timezone.utc) - timedelta(days=DEFAULT_TOKEN_LOG_LOOKBACK_DAYS)
            start_time = dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            logs = client.get_caa_activities(
                self.customer_id,
                start_time=start_time,
                max_items=self._get_max_log_events(),
            )
            self._propagate_client_errors(client)
            logger.info("Collected %d CAA events", len(logs))
            return logs
        except Exception as e:
            self._record_error("get_caa_activities", e)
            return []

    def _get_usage_reports(self) -> list:
        """Fetch usage reports."""
        try:
            from .api.reports import ReportsClient
            client = ReportsClient(self.auth)
            date = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%d")
            report = client.get_customer_usage_report(self.customer_id, date)
            self._propagate_client_errors(client)
            logger.info("Collected customer usage report")
            return report
        except Exception as e:
            self._record_error("get_usage_reports", e)
            return {}

    # Google Workspace SKU → (edition_label, license_tier_key) mapping.
    # license_tier_key matches keys in constants.LICENSE_TIERS so the
    # primary edition can be resolved by capability tier.
    #
    # Source: https://developers.google.com/workspace/admin/licensing/v1/how-tos/products
    # (Google's authoritative SKU reference; last cross-checked 2026-05-17)
    _GWS_PRODUCT_IDS = ("Google-Apps", "Google-Apps-For-Education")
    _SKU_EDITION_MAP: dict[str, tuple[str, str]] = {
        # --- Legacy G Suite (Google-Apps product) ---
        "Google-Apps-Lite":         ("Business Starter (Legacy)", "business_starter"),
        "Google-Apps-For-Business": ("Business (Legacy)",          "business_standard"),
        "Google-Apps-Unlimited":    ("Business Plus (Legacy)",     "business_plus"),
        # --- Google Workspace core editions (Google-Apps product, 1010020xxx) ---
        "1010020020": ("Google Workspace Enterprise Plus",        "enterprise_plus"),
        "1010020025": ("Google Workspace Business Plus",          "business_plus"),
        "1010020026": ("Google Workspace Enterprise Standard",    "enterprise_standard"),
        "1010020027": ("Google Workspace Business Starter",       "business_starter"),
        "1010020028": ("Google Workspace Business Standard",      "business_standard"),
        "1010020029": ("Google Workspace Enterprise Starter",     "enterprise_starter"),
        "1010020030": ("Google Workspace Frontline Starter",      "frontline_starter"),
        "1010020031": ("Google Workspace Frontline Standard",     "frontline_standard"),
        "1010020034": ("Google Workspace Frontline Plus",         "frontline_plus"),
        # --- Add-on / continuity SKUs (no tier_key — never drive primary edition) ---
        "1010020035": ("Google Workspace Business Continuity",      ""),
        "1010020036": ("Google Workspace Business Continuity Plus", ""),
        # --- Essentials (Google-Apps product, 1010060xxx) ---
        "1010060001": ("Google Workspace Essentials",                "essentials_starter"),
        "1010060003": ("Google Workspace Enterprise Essentials",     "enterprise_essentials"),
        "1010060005": ("Google Workspace Enterprise Essentials Plus","enterprise_essentials_plus"),
        # --- Education (Google-Apps-For-Education product) ---
        "1010310003": ("Google Workspace for Education Plus",                  "education_plus"),
        "1010310008": ("Google Workspace for Education Teaching & Learning",   "education_teaching_&_learning"),
        "1010310009": ("Google Workspace for Education Fundamentals",          "education_fundamentals"),
        "1010310010": ("Google Workspace for Education Standard",              "education_standard"),
        # --- Cloud Identity (informational; not a Workspace edition) ---
        "1010010001": ("Cloud Identity",                            ""),
        "1010050001": ("Cloud Identity Premium",                    ""),
    }

    @classmethod
    def _resolve_edition(cls, sku_id: str) -> tuple[str, str]:
        """Map a SKU ID to (edition_label, tier_key).  Unknown SKUs
        return ``("Unknown (SKU: <id>)", "")``."""
        return cls._SKU_EDITION_MAP.get(sku_id, (f"Unknown (SKU: {sku_id})", ""))

    @classmethod
    def _pick_primary_edition(
        cls, sku_counts: "Counter[str]"
    ) -> tuple[str, str]:
        """Pick the highest-tier edition from a Counter of SKU IDs.

        Cloud Identity SKUs (tier_key == "") are ignored — they are not
        a Workspace edition. Ties are broken by assignment count
        (most users wins), then by SKU id (stable).
        Returns ``("", "")`` when ``sku_counts`` is empty.
        """
        best_label = ""
        best_tier_key = ""
        best_tier = -1
        best_count = -1
        for sku_id, count in sku_counts.items():
            if count <= 0:
                continue
            label, tier_key = cls._resolve_edition(sku_id)
            tier = LICENSE_TIERS.get(tier_key, 0) if tier_key else 0
            if tier_key == "":
                continue  # Cloud Identity / unknown — not a Workspace tier
            better = (
                tier > best_tier
                or (tier == best_tier and count > best_count)
                or (tier == best_tier and count == best_count and sku_id < (best_label or ""))
            )
            if better:
                best_tier = tier
                best_count = count
                best_label = label
                best_tier_key = tier_key
        return best_label, best_tier_key

    def _list_license_assignments(self, product_id: str) -> list[dict]:
        """Page through licenseAssignments.listForProduct for a product.

        Returns a list of ``{"skuId": str, "userId": str}`` dicts.
        Returns ``[]`` if the API is unavailable for this product (e.g.
        Education product on a non-Education tenant returns 4xx).
        """
        items: list[dict] = []
        try:
            service = self.auth.build_service("licensing", "v1")
            page_token = None
            while True:
                request = service.licenseAssignments().listForProduct(
                    productId=product_id,
                    customerId=self.customer_id,
                    maxResults=500,
                    pageToken=page_token,
                )
                response = (
                    self.auth._execute_request(request)
                    if hasattr(self.auth, "_execute_request")
                    else request.execute()
                )
                items.extend(response.get("items", []))
                page_token = response.get("nextPageToken")
                if not page_token:
                    break
        except Exception as e:
            logger.debug(
                "Licensing API unavailable for product %s (optional): %s",
                product_id, e,
            )
        return items

    def _get_subscription_info(self) -> dict:
        """Detect the Google Workspace edition via the Licensing API.

        Pages through ``licenseAssignments.listForProduct`` for every
        Workspace product (Google-Apps and Google-Apps-For-Education),
        aggregates per-SKU assignment counts, and selects the
        highest-tier SKU as the tenant's primary edition (a tenant
        with mixed Enterprise + Frontline licenses is reported as
        Enterprise — the higher-tier features are available
        customer-wide).

        Returns a dict with::

            {
                "edition": "Google Workspace Enterprise Standard",
                "tier_key": "enterprise_standard",
                "skus": [
                    {"sku_id": "1010020027", "edition": "...",
                     "tier_key": "enterprise_standard", "count": 482},
                    ...
                ],
            }

        Falls back gracefully (empty edition) if the Licensing API is
        unavailable.
        """
        result: dict = {
            "edition": "",
            "tier_key": "",
            "skus": [],
            "tier_keys_present": [],
            "source": "",
        }
        sku_counts: Counter[str] = Counter()

        for product_id in self._GWS_PRODUCT_IDS:
            for item in self._list_license_assignments(product_id):
                sku_id = item.get("skuId", "")
                if sku_id:
                    sku_counts[sku_id] += 1

        if not sku_counts:
            logger.debug("No license assignments found for any Workspace product")
            return result

        logger.debug(
            "Detected SKU assignment counts: %s",
            dict(sku_counts.most_common()),
        )

        # Build per-SKU breakdown (sorted by count desc) for the report.
        breakdown = []
        tier_keys_present: set[str] = set()
        for sku_id, count in sku_counts.most_common():
            label, tier_key = self._resolve_edition(sku_id)
            breakdown.append({
                "sku_id": sku_id,
                "edition": label,
                "tier_key": tier_key,
                "count": count,
            })
            if tier_key:
                tier_keys_present.add(tier_key)
        result["skus"] = breakdown
        result["tier_keys_present"] = sorted(tier_keys_present)
        result["source"] = "licensing"

        edition, tier_key = self._pick_primary_edition(sku_counts)
        if edition:
            result["edition"] = edition
            result["tier_key"] = tier_key
            logger.info(
                "Detected subscription: %s (from %d distinct SKU(s); tiers present: %s)",
                edition, len(sku_counts),
                ", ".join(sorted(tier_keys_present)) or "none",
            )
        else:
            # Only Cloud Identity / unknown SKUs found — surface the most
            # common as a best-effort label so the user sees something.
            top_sku, _ = sku_counts.most_common(1)[0]
            label, _ = self._resolve_edition(top_sku)
            result["edition"] = label
            logger.info(
                "Detected non-Workspace SKU as primary: %s (%s)", label, top_sku,
            )
        return result

    def _get_alert_center_rules(self) -> list[dict]:
        """Fetch system-defined alert rules from the Alert Center API.

        Returns a list of dicts with ``name`` and ``enabled`` keys.
        Falls back to an empty list if the Alert Center API is unavailable
        (e.g. missing scope or insufficient license).
        """
        try:
            service = self.auth.build_service("alertcenter", "v1beta1")
            rules: list[dict] = []

            # The Alert Center API doesn't expose a rules endpoint directly.
            # We list recent alerts and infer active rule types from them.
            request = service.alerts().list(pageSize=100)
            response = request.execute()
            seen_types: set[str] = set()
            for alert in response.get("alerts", []):
                alert_type = alert.get("type", "")
                if alert_type and alert_type not in seen_types:
                    seen_types.add(alert_type)
                    rules.append({
                        "name": alert_type,
                        "enabled": True,
                        "source": "alert_center",
                    })

            logger.info("Collected %d alert types from Alert Center", len(rules))
            return rules
        except Exception as e:
            # Alert Center API is optional — not all editions support it
            # and the scope may not be delegated.
            logger.debug("Alert Center API unavailable: %s", e)
            return []

    def _get_group_members(self, groups: list[dict]) -> dict[str, list[dict]]:
        """Fetch members for each group."""
        if not groups:
            return {}
        try:
            from .api.directory import DirectoryClient
            client = DirectoryClient(self.auth)
            members_map: dict[str, list[dict]] = {}
            for group in groups:
                email = group.get("email", "")
                if email:
                    members = client.list_group_members(email)
                    members_map[email] = members
            self._propagate_client_errors(client)
            logger.info("Collected members for %d groups", len(members_map))
            return members_map
        except Exception as e:
            self._record_error("get_group_members", e)
            return {}

    def _get_chat_spaces(self) -> list[dict]:
        """Fetch Chat spaces via the Chat Admin API and resolve owners.

        For each space, resolves ROLE_MANAGER members to email addresses
        using the memberships API + user directory lookup.  Attaches an
        ``owner_emails`` list to every space dict.
        """
        try:
            from .api.chat_spaces import ChatSpacesClient
            from .api.directory import DirectoryClient
            client = ChatSpacesClient(self.auth)
            spaces = client.list_spaces()
            self._propagate_client_errors(client)
            logger.info("Collected %d Chat spaces", len(spaces))

            if not spaces:
                return spaces

            # Build a uid→email cache from already-fetched users to avoid
            # redundant directory lookups.
            uid_cache: dict[str, str] = {}
            dir_client: DirectoryClient | None = None

            for space in spaces:
                space_name = space.get("name", "")
                if not space_name:
                    space["owner_emails"] = []
                    continue

                owners = client.list_space_owners(space_name)
                owner_emails: list[str] = []

                for membership in owners:
                    user_id = membership.get("member", {}).get("name", "")
                    if not user_id:
                        continue

                    # Check cache first
                    if user_id in uid_cache:
                        email = uid_cache[user_id]
                        if email:
                            owner_emails.append(email)
                        continue

                    # Resolve via directory API
                    uid_num = user_id.replace("users/", "")
                    try:
                        if dir_client is None:
                            dir_client = DirectoryClient(self.auth)
                        user = dir_client.service.users().get(
                            userKey=uid_num
                        ).execute()
                        email = user.get("primaryEmail", "")
                        uid_cache[user_id] = email
                        if email:
                            owner_emails.append(email)
                    except Exception:
                        uid_cache[user_id] = ""

                space["owner_emails"] = owner_emails

            self._propagate_client_errors(client)
            return spaces
        except Exception as e:
            self._record_error("get_chat_spaces", e)
            return []

    def _get_mobile_devices(self) -> list[dict]:
        """Fetch mobile devices from the Directory API."""
        try:
            from .api.directory import DirectoryClient
            client = DirectoryClient(self.auth)
            devices = client.list_mobile_devices(self.customer_id)
            self._propagate_client_errors(client)
            logger.info("Collected %d mobile devices", len(devices))
            return devices
        except Exception as e:
            self._record_error("get_mobile_devices", e)
            return []

    def _get_chromeos_devices(self) -> list[dict]:
        """Fetch ChromeOS devices from the Directory API."""
        try:
            from .api.directory import DirectoryClient
            client = DirectoryClient(self.auth)
            devices = client.list_chromeos_devices(self.customer_id)
            self._propagate_client_errors(client)
            logger.info("Collected %d ChromeOS devices", len(devices))
            return devices
        except Exception as e:
            self._record_error("get_chromeos_devices", e)
            return []

    def _get_endpoint_devices(self) -> list[dict]:
        """Fetch endpoint verification devices from the Cloud Identity API.

        Covers Windows, Mac, and Linux devices managed via endpoint
        verification — devices not returned by the Admin SDK mobile or
        ChromeOS endpoints.
        """
        try:
            from .api.cloud_identity import CloudIdentityClient
            client = CloudIdentityClient(self.auth)
            devices = client.list_endpoint_devices(self.customer_id)
            self._propagate_client_errors(client)
            logger.info("Collected %d endpoint devices", len(devices))
            return devices
        except Exception as e:
            self._record_error("get_endpoint_devices", e)
            return []

    def _get_app_passwords(self) -> list[dict]:
        """Fetch App-Specific Passwords for all active users."""
        try:
            from .api.directory import DirectoryClient
            client = DirectoryClient(self.auth)
            users = self._get_users_and_admins()
            all_asps: list[dict] = []
            for user in users:
                if user.get("suspended"):
                    continue
                user_key = user.get("id") or user.get("primaryEmail", "")
                if not user_key:
                    continue
                asps = client.list_user_asps(user_key)
                for asp in asps:
                    asp["userEmail"] = user.get("primaryEmail", "")
                all_asps.extend(asps)
            self._propagate_client_errors(client)
            logger.info("Collected %d App-Specific Passwords", len(all_asps))
            return all_asps
        except Exception as e:
            self._record_error("get_app_passwords", e)
            return []

    def _get_user_tokens(self) -> list[dict]:
        """Fetch active OAuth tokens (third-party app grants) for all users.

        Uses the Admin SDK Directory ``tokens.list()`` endpoint to get
        **currently active** OAuth token grants per user.  This gives a
        point-in-time snapshot of which third-party apps have access,
        unlike token activity logs which are historical.

        Requires the ``admin.directory.user.security`` scope.
        """
        try:
            from .api.directory import DirectoryClient
            client = DirectoryClient(self.auth)
            users = self._get_users_and_admins()
            all_tokens: list[dict] = []
            for user in users:
                if user.get("suspended"):
                    continue
                email = user.get("primaryEmail", "")
                if not email:
                    continue
                tokens = client.list_user_tokens(email)
                for tok in tokens:
                    tok["userEmail"] = email
                all_tokens.extend(tokens)
            self._propagate_client_errors(client)
            logger.info("Collected %d active OAuth tokens", len(all_tokens))
            return all_tokens
        except Exception as e:
            self._record_error("get_user_tokens", e)
            return []

    def _get_shared_drives(self) -> list[dict]:
        """Fetch all Shared Drives with restrictions.

        When Drive SDK is disabled at the domain level, the Drive API
        returns HTTP 403 ``domainPolicy``.  This is an expected tenant
        configuration — not a setup error — so the message is logged at
        INFO level and suppressed from the API errors list.
        """
        try:
            from .api.drive import DriveClient
            client = DriveClient(self.auth)
            drives = client.list_shared_drives(self.customer_id)
            # Filter out domainPolicy errors — they indicate Drive SDK
            # is disabled at the tenant level, which is a policy choice.
            if hasattr(client, "errors") and client.errors:
                suppressed = []
                for err in client.errors:
                    msg = err.get("message", "") if isinstance(err, dict) else str(err)
                    if "domainPolicy" in msg or "disabled Drive apps" in msg:
                        logger.info(
                            "Drive SDK is disabled by domain policy — "
                            "skipping shared drives enumeration"
                        )
                    else:
                        suppressed.append(err)
                client.errors = suppressed
            self._propagate_client_errors(client)
            logger.info("Collected %d Shared Drives", len(drives))
            return drives
        except Exception as e:
            if "domainPolicy" in str(e) or "disabled Drive apps" in str(e):
                logger.info(
                    "Drive SDK is disabled by domain policy — "
                    "skipping shared drives enumeration"
                )
            else:
                self._record_error("get_shared_drives", e)
            return []

    def _detect_drive_sdk(self) -> bool | None:
        """Detect whether Drive SDK is enabled by probing the Drive API.

        Returns False (disabled), True (enabled), or None (indeterminate).
        """
        try:
            from .api.drive import DriveClient
            client = DriveClient(self.auth)
            result = client.is_drive_sdk_enabled()
            self._propagate_client_errors(client)
            return result
        except Exception as e:
            logger.debug("Drive SDK detection failed: %s", e)
            return None

    def _get_dns_records(self) -> dict:
        """Perform DNS lookups for all domains."""
        try:
            from .api.dns import DNSClient
            client = DNSClient()

            domains = self._get_domains()
            dns_data = {}
            for domain_info in domains:
                domain = domain_info.get("domainName", domain_info.get("domain", ""))
                if domain:
                    dns_data[domain] = client.check_all(domain)
                    logger.info("DNS checks complete for %s", domain)

            return dns_data
        except Exception as e:
            self._record_error("dns_lookups", e)
            return {}

    _MAX_CALENDAR_FALLBACK_ATTEMPTS = 3

    def _get_calendar_acls(self, data: dict) -> dict:
        """Fetch primary calendar ACLs to determine internal sharing level.

        Samples non-suspended users per OU and inspects the domain-scoped
        ACL rule on their primary calendar.  If a user's calendar returns a
        404, the next user in the same OU is tried (up to
        ``_MAX_CALENDAR_FALLBACK_ATTEMPTS`` attempts).

        Returns a dict keyed by OU path::

            {"/": {"role": "freeBusyReader", "sampled_user": "admin@example.com"}, ...}
        """
        users = data.get("users", [])
        domains = data.get("domains", [])
        if not users or not domains:
            return {}

        primary_domain = next(
            (d["domainName"] for d in domains if d.get("isPrimary")),
            domains[0].get("domainName", "") if domains else "",
        )
        if not primary_domain:
            return {}

        # Group all non-suspended users by OU (preserving order).
        # Prioritize primary-domain users: cross-domain users may lack
        # delegation and cause unauthorized_client errors.
        ou_primary: dict[str, list[str]] = {}
        ou_other: dict[str, list[str]] = {}
        for u in users:
            if u.get("suspended"):
                continue
            ou = u.get("orgUnitPath", u.get("org_unit_path", "/")) or "/"
            email = u.get("primaryEmail", u.get("primary_email", ""))
            if email:
                if email.endswith(f"@{primary_domain}"):
                    ou_primary.setdefault(ou, []).append(email)
                else:
                    ou_other.setdefault(ou, []).append(email)
        ou_users: dict[str, list[str]] = {}
        all_ous = set(ou_primary) | set(ou_other)
        for ou in all_ous:
            ou_users[ou] = ou_primary.get(ou, []) + ou_other.get(ou, [])

        if not ou_users:
            return {}

        try:
            from .api.calendar import CalendarClient, CalendarNotFoundError
            client = CalendarClient(self.auth)
            results = {}

            for ou, emails in ou_users.items():
                max_attempts = min(
                    self._MAX_CALENDAR_FALLBACK_ATTEMPTS, len(emails)
                )
                for email in emails[:max_attempts]:
                    try:
                        acl_rules = client.get_calendar_acl(email, email)
                    except CalendarNotFoundError:
                        logger.warning(
                            "Calendar 404 for %s in OU %s, trying next user",
                            email,
                            ou,
                        )
                        continue

                    if not acl_rules:
                        # Empty result — likely an auth/delegation error
                        # (e.g. unauthorized_client for cross-domain users).
                        logger.debug(
                            "Empty ACL for %s in OU %s, trying next user",
                            email,
                            ou,
                        )
                        continue

                    domain_rule = next(
                        (r for r in acl_rules
                         if r.get("scope", {}).get("type") == "domain"
                         and r.get("scope", {}).get("value") == primary_domain),
                        None,
                    )
                    if domain_rule:
                        results[ou] = {
                            "role": domain_rule.get("role", ""),
                            "sampled_user": email,
                        }
                    break  # Got a response with data, stop trying

            self._propagate_client_errors(client)
            logger.info("Collected calendar ACLs for %d OU(s)", len(results))
            return results
        except Exception as e:
            self._record_error("get_calendar_acls", e)
            return {}

    def _record_error(self, operation: str, error: Exception):
        """Record an API error for reporting."""
        err = {"operation": operation, "error": str(error), "type": type(error).__name__}
        self._api_errors.append(err)
        logger.exception("API error in %s: %s", operation, error)

    def _save_cache(self, data: dict, partial: bool = False):
        """Save collected data to cache directory.

        Parameters
        ----------
        data:
            The collected data dict.
        partial:
            If True, save to ``gws_data_partial.json`` (overwritten each time).
            If False, save to a timestamped file and remove any partial cache.
        """
        cache_dir = self.options.get("cache_directory", "./cache")
        os.makedirs(cache_dir, exist_ok=True)

        # Make data JSON-serializable
        serializable = _make_serializable(data)

        if partial:
            cache_file = os.path.join(cache_dir, "gws_data_partial.json")
            with open(cache_file, "w") as f:
                json.dump(serializable, f, indent=2, default=str)
            logger.info("Saved partial cache to %s", cache_file)
        else:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            cache_file = os.path.join(cache_dir, f"gws_data_{timestamp}.json")
            with open(cache_file, "w") as f:
                json.dump(serializable, f, indent=2, default=str)
            logger.info("Cached data to %s", cache_file)
            # Remove partial cache if it exists
            partial_file = os.path.join(cache_dir, "gws_data_partial.json")
            if os.path.exists(partial_file):
                os.remove(partial_file)
                logger.info("Removed partial cache %s", partial_file)

    @classmethod
    def from_cache(cls, cache_path: str) -> dict:
        """Load previously cached data from a file or directory."""
        if os.path.isdir(cache_path):
            # Find most recent cache file
            files = sorted(
                [f for f in os.listdir(cache_path) if f.startswith("gws_data_")],
                reverse=True,
            )
            if not files:
                raise FileNotFoundError(f"No cache files found in {cache_path}")
            cache_path = os.path.join(cache_path, files[0])

        with open(cache_path, "r") as f:
            data = json.load(f)

        logger.info("Loaded cached data from %s", cache_path)
        # Normalize raw API data into the format checks expect
        return normalize_data(data)

    @classmethod
    def from_partial_cache(cls, cache_dir: str) -> dict | None:
        """Load partial cache from a previous interrupted run.

        Returns the raw (unnormalized) data dict, or None if no partial
        cache exists.
        """
        partial_path = os.path.join(cache_dir, "gws_data_partial.json")
        if not os.path.exists(partial_path):
            return None

        with open(partial_path, "r") as f:
            data = json.load(f)

        logger.info("Loaded partial cache from %s", partial_path)
        return data

    def collect_all_resumable(self, resume_data: dict | None = None) -> dict:
        """Collect data with resume support.

        If *resume_data* is provided, reads ``_collection_metadata`` to
        determine which endpoints have already been collected and skips them.
        After each endpoint completes, a partial cache is saved for crash
        resilience.
        """
        logger.info("Starting resumable data collection...")

        metadata = {}
        if resume_data:
            metadata = resume_data.get("_collection_metadata", {})

        completed_endpoints = set(metadata.get("completed_endpoints", []))
        data = resume_data.copy() if resume_data else {}
        data.setdefault("api_errors", [])
        self._api_errors = data.get("api_errors", [])

        if "_collection_metadata" not in data:
            data["_collection_metadata"] = {
                "started_at": datetime.now(timezone.utc).isoformat(),
                "completed_at": None,
                "completed_endpoints": [],
                "failed_endpoints": [],
                "version": "1.0",
            }

        for data_key, method_name in self.COLLECTION_ENDPOINTS:
            if data_key in completed_endpoints:
                logger.info("Skipping already-collected endpoint: %s", data_key)
                continue

            logger.info("Collecting endpoint: %s", data_key)
            try:
                method = getattr(self, method_name)
                # group_members needs groups as argument
                if data_key == "group_members":
                    result = method(data.get("groups", []))
                else:
                    result = method()
                data[data_key] = result
                data["_collection_metadata"]["completed_endpoints"].append(data_key)
            except Exception as e:
                logger.exception("Failed to collect %s: %s", data_key, e)
                self._record_error(data_key, e)
                data["_collection_metadata"]["failed_endpoints"].append(data_key)

            # Save partial cache after each endpoint
            data["api_errors"] = self._api_errors
            if self.options.get("cache_data", True):
                self._save_cache(data, partial=True)

        # Backfill org units, collect calendar_acls, detect Drive SDK
        self._backfill_org_units(data)
        data["calendar_acls"] = self._get_calendar_acls(data)
        data.setdefault("drive_sdk_enabled", self._detect_drive_sdk())
        data["collection_timestamp"] = datetime.now(timezone.utc).isoformat()
        data["_collection_metadata"]["completed_at"] = datetime.now(timezone.utc).isoformat()
        data["api_errors"] = self._api_errors

        # Save final cache (removes partial)
        if self.options.get("cache_data", True):
            self._save_cache(data)

        # Normalize
        data = normalize_data(data)

        logger.info(
            "Resumable data collection complete. API errors: %d",
            len(self._api_errors),
        )
        return data


def _make_serializable(obj):
    """Convert an object to be JSON-serializable."""
    if isinstance(obj, dict):
        return {k: _make_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [_make_serializable(item) for item in obj]
    elif isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    else:
        return str(obj)


# -----------------------------------------------------------------------
# Data normalization — bridge between raw API responses and check format
# -----------------------------------------------------------------------

def normalize_data(data: dict) -> dict:
    """Normalize raw Google API data into the format checks expect.

    The Google APIs return camelCase field names and nested structures.
    Checks expect snake_case field names and specific dict layouts.
    This function bridges the gap so checks work with both fresh API
    data and cached data.
    """
    ou_id_map = _build_ou_id_map(data.get("org_units", []))
    data["users"] = _normalize_users(data.get("users", []))
    data["policies"] = _normalize_policies(data.get("policies", {}), ou_id_map)
    data["policies"] = _map_policies_to_check_schema(data["policies"])
    _map_chrome_policies(data["policies"], data.get("chrome_policies", {}))
    data["admin_logs"] = _normalize_activity_logs(data.get("admin_logs", []))
    data["login_logs"] = _normalize_activity_logs(data.get("login_logs", []))
    data["token_logs"] = _normalize_activity_logs(data.get("token_logs", []))
    data["caa_events"] = _normalize_activity_logs(data.get("caa_events", []))
    data["dns_records"] = _normalize_dns_records(data.get("dns_records", {}))
    # Ensure new data keys have safe defaults
    data.setdefault("group_members", {})
    data.setdefault("chat_spaces", [])
    data.setdefault("mobile_devices", [])
    data.setdefault("chromeos_devices", [])
    data.setdefault("endpoint_devices", [])
    data.setdefault("app_passwords", [])
    data.setdefault("user_tokens", [])
    data.setdefault("shared_drives", [])
    data.setdefault("subscription_info", {})
    data.setdefault("_options", {})
    _validate_schema(data)
    return data


def _validate_schema(data: dict) -> None:
    """Soft-validate normalized data against the Pydantic schema contract.

    Never raises — logs a warning if validation finds structural issues.
    ImportError-safe so the tool works even if pydantic is not installed.
    """
    try:
        from .schemas import AuditData
        AuditData.model_validate(data)
    except ImportError:
        pass  # pydantic not installed
    except Exception as e:
        logger.warning("Schema validation issue: %s", e)


def _normalize_users(users: list) -> list:
    """Add snake_case aliases for Google Admin SDK user fields.

    The Admin SDK Directory API returns camelCase fields (isAdmin,
    primaryEmail, isEnrolledIn2Sv, etc.). Checks reference snake_case
    names (is_super_admin, primary_email, is_enrolled_in_2sv).
    We keep original fields and add snake_case aliases.
    """
    normalized = []
    for u in users:
        if not isinstance(u, dict):
            normalized.append(u)
            continue
        # Skip if already normalized (has snake_case fields)
        if "primary_email" in u:
            normalized.append(u)
            continue
        u.update({
            "primary_email": u.get("primaryEmail", ""),
            "is_super_admin": u.get("isAdmin", False),
            "is_admin": u.get("isAdmin", False),
            "is_delegated_admin": u.get("isDelegatedAdmin", False),
            "is_enrolled_in_2sv": u.get("isEnrolledIn2Sv", False),
            "is_enforced_in_2sv": u.get("isEnforcedIn2Sv", False),
            "last_login_time": u.get("lastLoginTime", ""),
            "creation_time": u.get("creationTime", ""),
            "org_unit_path": u.get("orgUnitPath", "/"),
            "suspended": u.get("suspended", False),
            "recovery_email": u.get("recoveryEmail", ""),
            "recovery_phone": u.get("recoveryPhone", ""),
        })
        normalized.append(u)
    return normalized


def _build_ou_id_map(org_units: list) -> dict[str, str]:
    """Build a mapping from orgUnitId → orgUnitPath.

    The Cloud Identity Policy API returns orgUnit values in the format
    ``orgUnits/<id>`` but checks and reports display human-readable
    paths like ``/Engineering``.  This map enables the translation.

    Returns an empty dict when org_units is empty (single-OU tenants).
    """
    id_map: dict[str, str] = {}
    for ou in org_units:
        if not isinstance(ou, dict):
            continue
        ou_id = ou.get("orgUnitId", "")
        ou_path = ou.get("orgUnitPath", "")
        if ou_id and ou_path:
            # Store with and without the "id:" prefix for flexibility
            id_map[ou_id] = ou_path
            # Strip the "id:" prefix if present
            bare_id = ou_id.removeprefix("id:")
            if bare_id != ou_id:
                id_map[bare_id] = ou_path
            # Also store the orgUnits/<id> format used by the Policy API
            id_map[f"orgUnits/{bare_id}"] = ou_path
    return id_map


def _resolve_org_unit(raw_ou: str, ou_id_map: dict[str, str]) -> str:
    """Resolve an ``orgUnits/<id>`` value to a human-readable path.

    Falls through to the raw value when no mapping is found.
    """
    if not raw_ou or raw_ou == "/":
        return "/"
    # Direct lookup first (handles orgUnits/<id> and bare IDs already in map)
    direct = ou_id_map.get(raw_ou)
    if direct:
        return direct
    if raw_ou.startswith("orgUnits/"):
        ou_id = raw_ou.split("/", 1)[1]
        return ou_id_map.get(ou_id, ou_id_map.get(f"id:{ou_id}", raw_ou))
    return raw_ou


def _normalize_policies(policies, ou_id_map: dict[str, str] | None = None) -> dict:
    """Convert policy lists to nested dicts keyed by setting name.

    The Cloud Identity Policy API returns a list of policy resources per
    category.  Each resource has a ``setting`` dict with ``type`` (e.g.
    ``settings/gmail.confidential_mode``) and ``value`` (the payload).

    Checks expect a nested dict so they can drill into settings via
    ``.get()`` chains like ``policies["security"]["password"]["minLength"]``.

    This function converts each category's list into a dict keyed by the
    setting-specific name (e.g. ``confidential_mode``) with the setting
    ``value`` payload as the dict value.  When the API returns no data
    (empty list), the category becomes an empty dict so checks gracefully
    degrade to MANUAL results.
    """
    if ou_id_map is None:
        ou_id_map = {}
    if not isinstance(policies, dict):
        return {}

    normalized = {}
    for category, value in policies.items():
        if isinstance(value, dict):
            # Already a dict — resolve any lingering orgUnit IDs in
            # _ou_policies (e.g. cached data from an older version) and
            # attach the map for downstream use by get_ou_values().
            if "_ou_policies" in value and ou_id_map:
                for policy in value["_ou_policies"]:
                    if isinstance(policy, dict):
                        raw_ou = policy.get("orgUnit", "/")
                        if raw_ou.startswith("orgUnits/"):
                            policy["orgUnit"] = _resolve_org_unit(raw_ou, ou_id_map)
            if ou_id_map:
                value["_ou_id_map"] = ou_id_map
            normalized[category] = value
        elif isinstance(value, list):
            if not value:
                normalized[category] = {}
            else:
                cat_dict = {}
                # Preserve the full per-OU policy list so checks can
                # evaluate each OU independently.
                cat_dict["_ou_policies"] = value
                # Store the OU ID map so get_ou_values() can perform
                # secondary resolution if any IDs were missed.
                if ou_id_map:
                    cat_dict["_ou_id_map"] = ou_id_map

                # Resolve orgUnits/<id> to readable paths
                for policy in value:
                    if isinstance(policy, dict):
                        raw_ou = policy.get("orgUnit", "/")
                        policy["orgUnit"] = _resolve_org_unit(raw_ou, ou_id_map)

                # Sort so root OU "/" comes last and wins in dict
                # assignment when multiple OUs define the same setting.
                sorted_policies = sorted(
                    value,
                    key=lambda p: (p.get("orgUnit", "/") == "/"),
                )

                for policy in sorted_policies:
                    if not isinstance(policy, dict):
                        continue

                    setting = policy.get("setting", {})
                    setting_type = ""
                    setting_value = setting

                    if isinstance(setting, dict):
                        setting_type = setting.get("type", "")
                        # The actual payload lives under "value"; fall
                        # back to the whole setting dict if absent.
                        setting_value = setting.get("value", setting)

                        # Normalise field names: the Cloud Identity
                        # Policy API returns snake_case keys in the
                        # value dict, but downstream code may use
                        # camelCase.  Add both variants so lookups
                        # work regardless of convention.
                        if (isinstance(setting_value, dict)
                                and setting_value is not setting):
                            _dual_case_keys(setting_value)

                    # Derive a dict key from the setting type.
                    # E.g. "settings/gmail.confidential_mode" → "confidential_mode"
                    # E.g. "settings/security.password" → "password"
                    key = ""
                    if setting_type:
                        # Strip "settings/" prefix, then category prefix
                        bare = setting_type
                        if bare.startswith("settings/"):
                            bare = bare[len("settings/"):]
                        # Remove the category prefix (e.g. "gmail.")
                        if "." in bare:
                            key = bare.split(".", 1)[1]
                        else:
                            key = bare
                    if not key:
                        # Fallback: try policy resource name
                        name = policy.get("name", "")
                        if "/" in name:
                            key = name.rsplit("/", 1)[-1]
                        elif "." in name:
                            key = name.rsplit(".", 1)[-1]
                        else:
                            key = name or f"policy_{len(cat_dict)}"

                    key = key.lower()
                    cat_dict[key] = setting_value
                normalized[category] = cat_dict
        else:
            normalized[category] = {}

    return normalized


def _parse_duration_seconds(duration_str: str) -> int:
    """Parse a protobuf duration string like '1209600s' to integer seconds."""
    if not duration_str:
        return 0
    s = duration_str.strip()
    if s.endswith("s"):
        s = s[:-1]
    try:
        return int(float(s))
    except (ValueError, TypeError):
        return 0


def _map_policies_to_check_schema(policies: dict) -> dict:
    """Map flat API policy keys to the nested structure check functions expect.

    After ``_normalize_policies()`` converts API lists to flat dicts keyed
    by setting name (e.g. ``gmail["email_attachment_safety"]``), this
    function creates the deeper nested keys that check functions navigate
    with ``.get()`` chains (e.g. ``gmail["safety"]["attachments"][...]``).

    The original flat keys are preserved alongside the new nested keys.
    """
    if not isinstance(policies, dict):
        return policies

    _map_gmail(policies)
    _map_drive(policies)
    _map_calendar(policies)
    _map_chat(policies)
    _map_meet(policies)
    _map_sites(policies)
    _map_classroom(policies)
    _map_security(policies)
    _map_data_regions(policies)
    _map_api_controls_to_security(policies)
    _map_groups(policies)
    _map_marketplace(policies)
    _map_directory(policies)
    _map_multi_party_approval(policies)
    _map_rules(policies)

    return policies


def _map_gmail(policies: dict) -> None:
    """Map Gmail API settings to the nested keys Gmail checks expect."""
    gmail = policies.get("gmail", {})
    if not gmail or not isinstance(gmail, dict):
        return

    # --- Attachment safety → safety.attachments ---
    att = gmail.get("email_attachment_safety", {})
    if isinstance(att, dict) and att:
        gmail.setdefault("safety", {}).setdefault("attachments", {}).update({
            "encrypted_attachment_protection": att.get("enableEncryptedAttachmentProtection"),
            "script_attachment_protection": att.get("enableAttachmentWithScriptsProtection"),
            "anomalous_attachment_protection": att.get("enableAnomalousAttachmentProtection"),
        })

    # --- Links and external images → safety.links ---
    links = gmail.get("links_and_external_images", {})
    if isinstance(links, dict) and links:
        gmail.setdefault("safety", {}).setdefault("links", {}).update({
            "scan_shortened_urls": links.get("enableShortenerScanning"),
            "scan_linked_images": links.get("enableExternalImageScanning"),
            "show_warning_for_untrusted_links": links.get("enableAggressiveWarningsOnUntrustedLinks"),
        })

    # --- Spoofing and authentication → safety.spoofing ---
    spoof = gmail.get("spoofing_and_authentication", {})
    if isinstance(spoof, dict) and spoof:
        gmail.setdefault("safety", {}).setdefault("spoofing", {}).update({
            "domain_spoofing_protection": spoof.get("detectDomainNameSpoofing"),
            "employee_name_spoofing_protection": spoof.get("detectEmployeeNameSpoofing"),
            "inbound_domain_spoofing_protection": spoof.get("detectDomainSpoofingFromUnauthenticatedSenders"),
            "unauthenticated_email_protection": spoof.get("detectUnauthenticatedEmails"),
            "groups_spoofing_protection": spoof.get("detectGroupsSpoofing"),
        })

    # --- Enhanced pre-delivery message scanning → safety.enhanced_predelivery_scanning ---
    predelivery = gmail.get("enhanced_pre_delivery_message_scanning", {})
    if isinstance(predelivery, dict) and predelivery:
        gmail.setdefault("safety", {})["enhanced_predelivery_scanning"] = (
            predelivery.get("enableImprovedSuspiciousContentDetection")
        )

    # --- Confidential mode ---
    conf = gmail.get("confidential_mode", {})
    if isinstance(conf, dict) and conf:
        gmail.setdefault("confidential_mode_settings", {})["enabled"] = (
            conf.get("enableConfidentialMode")
        )

    # --- S/MIME encryption ---
    smime = gmail.get("enhanced_smime_encryption", {})
    if isinstance(smime, dict) and smime:
        gmail.setdefault("encryption", {})["smime_user_upload"] = (
            smime.get("allowUserToUploadCertificates")
        )

    # Flatten service_status dict to string
    ss = gmail.get("service_status")
    if isinstance(ss, dict):
        state = ss.get("serviceState", "")
        if state:
            gmail["service_status"] = state.lower()

    # --- User email uploads → user_settings ---
    uploads = gmail.get("user_email_uploads", {})
    if isinstance(uploads, dict) and uploads:
        import_enabled = uploads.get("enableMailAndContactsImport")
        us = gmail.setdefault("user_settings", {})
        us["mail_import_enabled"] = import_enabled
        us["email_uploads_enabled"] = import_enabled  # alias for CISA checks

    # --- Mail delegation ---
    md = gmail.get("mail_delegation", {})
    if isinstance(md, dict) and md:
        enabled = md.get("enableMailDelegation", md.get("enabled"))
        if enabled is not None:
            gmail.setdefault("user_settings", {})["mail_delegation_enabled"] = enabled

    # --- POP access ---
    pop = gmail.get("pop_access", {})
    if isinstance(pop, dict) and pop:
        enabled = pop.get("enablePop3Access", pop.get("enablePopAccess", pop.get("enabled")))
        if enabled is not None:
            gmail.setdefault("end_user_access", {})["pop_enabled"] = enabled

    # --- IMAP access ---
    imap = gmail.get("imap_access", {})
    if isinstance(imap, dict) and imap:
        enabled = imap.get("enableImapAccess", imap.get("enabled"))
        if enabled is not None:
            gmail.setdefault("end_user_access", {})["imap_enabled"] = enabled

    # --- Auto-forwarding ---
    af = gmail.get("auto_forwarding", {})
    if isinstance(af, dict) and af:
        enabled = af.get("enableAutoForwarding", af.get("enabled"))
        if enabled is not None:
            gmail.setdefault("routing", {})["auto_forwarding_enabled"] = enabled

    # --- Per-user outbound gateway ---
    gw = gmail.get("per_user_outbound_gateway", {})
    if isinstance(gw, dict) and gw:
        enabled = gw.get("allowUsersToUseExternalSmtpServers",
                         gw.get("enablePerUserOutboundGateway", gw.get("enabled")))
        if enabled is not None:
            gmail.setdefault("routing", {})["per_user_outbound_gateway_enabled"] = enabled

    # --- Comprehensive mail storage ---
    cms = gmail.get("comprehensive_mail_storage", {})
    if isinstance(cms, dict) and cms:
        enabled = cms.get("enableComprehensiveMailStorage", cms.get("enabled"))
        if enabled is not None:
            comp = gmail.setdefault("compliance", {})
            comp["comprehensive_mail_storage"] = enabled
            comp["comprehensive_mail_storage_enabled"] = enabled

    # --- Workspace Sync for Outlook ---
    wsync = gmail.get("workspace_sync_for_outlook", {})
    if isinstance(wsync, dict) and wsync:
        enabled = wsync.get("enableGoogleWorkspaceSyncForMicrosoftOutlook",
                            wsync.get("enableWorkspaceSync",
                                      wsync.get("enableGoogleWorkspaceSync", wsync.get("enabled"))))
        if enabled is not None:
            gmail.setdefault("end_user_access", {})["workspace_sync_enabled"] = enabled

    # --- Content compliance → compliance ---
    # The Policy API surfaces user-defined content-compliance rules under
    # ``content_compliance.contentComplianceRules``. These rules implement
    # Gmail DLP (and other content-routing logic), so expose the raw rule
    # list to checks that look for DLP coverage.
    cc = gmail.get("content_compliance", {})
    if isinstance(cc, dict) and cc:
        comp = gmail.setdefault("compliance", {})
        comp["content_compliance_configured"] = True
        rules = cc.get("contentComplianceRules", cc.get("content_compliance_rules"))
        if isinstance(rules, list):
            comp["content_compliance_rules"] = rules

    # --- Spam override lists → spam_settings ---
    sol = gmail.get("spam_override_lists", {})
    if isinstance(sol, dict) and sol:
        domains = sol.get("approvedSendersDomains", sol.get("domains", []))
        if isinstance(domains, list):
            ss = gmail.setdefault("spam_settings", {})
            ss["approved_senders_domains"] = domains
        bypass_domains = sol.get("domainsBypassAndHideWarnings", sol.get("bypassDomains", []))
        if isinstance(bypass_domains, list):
            ss = gmail.setdefault("spam_settings", {})
            ss["domains_bypass_and_hide_warnings"] = bypass_domains

    # --- Email spam filter IP allowlist ---
    # The Cloud Identity Policy API exposes inbound-gateway state via the
    # spam-filter IP allowlist. A non-empty list means a gateway is in use;
    # an explicit empty list means no gateway is configured (Google handles
    # SPF directly). The reject-on-SPF-fail setting itself isn't exposed by
    # this API — checks treat it as MANUAL when a gateway is configured.
    spf_al = gmail.get("email_spam_filter_ip_allowlist", {})
    if isinstance(spf_al, dict):
        ips = spf_al.get("allowedIpAddresses", spf_al.get("allowed_ip_addresses"))
        if isinstance(ips, list):
            gmail.setdefault("inbound_gateway", {})["configured"] = bool(ips)
        elif spf_al:
            gmail.setdefault("inbound_gateway", {})["configured"] = True


def _map_drive(policies: dict) -> None:
    """Map Drive API settings to the nested keys Drive checks expect."""
    drive = policies.get("drive", {})
    if not drive or not isinstance(drive, dict):
        return

    # --- Shared Drive creation → shared_drive_settings ---
    sd = drive.get("shared_drive_creation", {})
    if isinstance(sd, dict) and sd:
        # Note: API uses "allow" booleans; checks use "restricted" booleans
        # so some values are inverted.
        allow_creation = sd.get("allowSharedDriveCreation")
        allow_override = sd.get("allowManagersToOverrideSettings")
        allow_non_member = sd.get("allowNonMemberAccess")
        download_parties = sd.get("allowedPartiesForDownloadPrintCopy", "")
        allow_external = sd.get("allowExternalUserAccess")

        sds = drive.setdefault("shared_drive_settings", {})
        if allow_creation is not None:
            sds["creation_restricted"] = not allow_creation
        if allow_override is not None:
            sds["manager_can_override"] = allow_override
            sds["allow_manager_override"] = allow_override  # alias for CISA checks
        if allow_non_member is not None:
            sds["access_restricted_to_members"] = not allow_non_member
            sds["allow_non_member_access"] = allow_non_member  # alias for CISA checks
        if download_parties:
            sds["viewer_download_print_copy_disabled"] = (
                download_parties not in ("ALL", "EDITORS_AND_ABOVE")
            )
        if allow_external is not None:
            sds["allow_external_user_access"] = allow_external

    # --- File security update → features ---
    fsu = drive.get("file_security_update", {})
    if isinstance(fsu, dict) and fsu:
        update_val = fsu.get("securityUpdate", "")
        if update_val:
            drive.setdefault("features", {})["security_update_for_files"] = (
                update_val == "APPLY_TO_IMPACTED_FILES"
            )

    # --- Drive for Desktop → features ---
    dfd = drive.get("drive_for_desktop", {})
    if isinstance(dfd, dict) and dfd:
        feats = drive.setdefault("features", {})
        allow_desktop = dfd.get("allowDriveForDesktop")
        if allow_desktop is not None:
            feats["desktop_access_enabled"] = allow_desktop
            feats["desktop_allowed"] = allow_desktop  # alias for CISA checks

    # --- External file warning → sharing_settings.out_of_domain_warning_enabled ---
    # The Policy API surfaces this as ``external_file_warning.highlightingEnabled``.
    efw = drive.get("external_file_warning", {})
    if isinstance(efw, dict) and efw:
        ood = efw.get("highlightingEnabled",
                      efw.get("outOfDomainWarningEnabled",
                              efw.get("out_of_domain_warning_enabled")))
        if ood is not None:
            drive.setdefault("sharing_settings", {})["out_of_domain_warning_enabled"] = ood

    # --- External sharing → sharing_settings ---
    es = drive.get("external_sharing", {})
    if isinstance(es, dict) and es:
        ss = drive.setdefault("sharing_settings", {})
        # Map various fields from the external_sharing payload
        warn = es.get("warnForExternalSharing",
                      es.get("warnOnExternalSharing"))
        if warn is not None:
            ss["warn_on_external_sharing"] = warn
            ss["warn_for_external_sharing"] = warn
        pub = es.get("allowPublishingFiles",
                     es.get("allowPublicPublishing", es.get("allowPublishingOutsideDomain")))
        if pub is not None:
            ss["allow_public_publishing"] = pub
        al = es.get("allowlistedDomainsEnabled", es.get("whitelistedDomainsEnabled"))
        if al is not None:
            ss["allowlisted_domains_enabled"] = al
        al_warn = es.get("warnOnAllowlistedDomainSharing")
        if al_warn is not None:
            ss["warn_on_allowlisted_domain_sharing"] = al_warn
        checker = es.get("accessCheckerSuggestion", es.get("accessChecker", ""))
        if checker:
            ss["access_checker_suggestion"] = checker.lower()
            ss["access_checker_suggestions"] = checker.lower()
        dist = es.get("externalDistributionAllowedFor", es.get("distributionAllowedFor", ""))
        if dist:
            ss["external_distribution_allowed_for"] = dist.lower()
        recv = es.get("allowReceivingFilesFromNonAllowlisted",
                      es.get("receiveFilesOutsideDomain"))
        if recv is not None:
            ss["receive_files_from_non_allowlisted"] = recv
        non_google = es.get("sharingWithNonGoogleUsers",
                            es.get("allowNonGoogleAccountSharing"))
        if non_google is not None:
            ss["allow_non_google_account_sharing"] = non_google
        anyone_link = es.get("anyoneWithLinkEnabled",
                             es.get("allowAnyoneWithLink"))
        if anyone_link is not None:
            ss["anyone_with_link_enabled"] = anyone_link
        ext_upload = es.get("allowUploadToExternalDrives",
                            es.get("allowExternalDriveUpload"))
        if ext_upload is not None:
            ss["allow_upload_to_external_drives"] = ext_upload
        ood_warn = es.get("outOfDomainWarningEnabled",
                          es.get("warnOutOfDomain"))
        if ood_warn is not None:
            ss["out_of_domain_warning_enabled"] = ood_warn

    # --- General access default → sharing_settings ---
    gad = drive.get("general_access_default", {})
    if isinstance(gad, dict) and gad:
        default_access = (
            gad.get("defaultFileAccess", "")
            or gad.get("defaultLinkSharingAccess", "")
            or gad.get("defaultAccess", "")
            or gad.get("generalAccessDefault", "")
        )
        if default_access:
            ss = drive.setdefault("sharing_settings", {})
            ss["default_link_sharing_access"] = default_access.lower()

    # --- Drive SDK → features ---
    # The Policy API exposes Drive Add-Ons availability via
    # ``drive_sdk.enableDriveSdkApiAccess``: when SDK access is on, third-party
    # Drive Add-Ons (which install through the SDK surface) are available.
    sdk = drive.get("drive_sdk", {})
    if isinstance(sdk, dict) and sdk:
        enabled = sdk.get("enableDriveSdkApiAccess",
                          sdk.get("enableDriveSdk", sdk.get("enabled")))
        if enabled is not None:
            feats = drive.setdefault("features", {})
            feats["drive_sdk_enabled"] = enabled
            feats["add_ons_enabled"] = enabled

    # Flatten service_status dict to string
    ss_raw = drive.get("service_status")
    if isinstance(ss_raw, dict):
        state = ss_raw.get("serviceState", "")
        if state:
            drive["service_status"] = state.lower()


def _map_calendar(policies: dict) -> None:
    """Map Calendar API settings to the nested keys Calendar checks expect."""
    cal = policies.get("calendar", {})
    if not cal or not isinstance(cal, dict):
        return

    # --- Appointment schedules → appointments ---
    aps = cal.get("appointment_schedules", {})
    if isinstance(aps, dict) and aps:
        enable_pay = aps.get("enablePayments")
        if enable_pay is not None:
            cal.setdefault("appointments", {})["paid_appointments_enabled"] = enable_pay

    # --- Primary calendar max allowed external sharing ---
    pcm = cal.get("primary_calendar_max_allowed_external_sharing", {})
    if isinstance(pcm, dict) and pcm:
        sharing = (
            pcm.get("maxAllowedExternalSharing", "")
            or pcm.get("sharingLevel", "")
            or pcm.get("accessLevel", "")
        )
        if sharing:
            _SHARING_MAP = {
                "FREE_BUSY_ONLY": "only_free_busy",
                "ONLY_FREE_BUSY": "only_free_busy",
                "ALL_INFORMATION": "all_information",
                "READ_WRITE_ACCESS": "read_write_access",
                "MANAGE_ACCESS": "read_write_access",
                "EXTERNAL_NO_FREE_BUSY": "no_sharing",
                "EXTERNAL_FREE_BUSY_ONLY": "only_free_busy",
                "EXTERNAL_ALL_INFO_READ_ONLY": "all_information",
                "EXTERNAL_ALL_INFO_READ_WRITE_MANAGE": "read_write_access",
            }
            pc = cal.setdefault("primary_calendar", {})
            pc["external_sharing"] = _SHARING_MAP.get(sharing, sharing.lower())

    # --- Primary calendar max allowed internal sharing ---
    pcm_int = cal.get("primary_calendar_max_allowed_internal_sharing", {})
    if isinstance(pcm_int, dict) and pcm_int:
        sharing = (
            pcm_int.get("maxAllowedInternalSharing", "")
            or pcm_int.get("sharingLevel", "")
            or pcm_int.get("accessLevel", "")
        )
        if sharing:
            _INT_SHARING_MAP = {
                "FREE_BUSY_ONLY": "only_free_busy",
                "ONLY_FREE_BUSY": "only_free_busy",
                "ALL_INFORMATION": "all_information",
                "READ_WRITE_ACCESS": "read_write_access",
                "MANAGE_ACCESS": "read_write_access",
            }
            pc = cal.setdefault("primary_calendar", {})
            pc["internal_sharing"] = _INT_SHARING_MAP.get(sharing, sharing.lower())

    # --- Secondary calendar max allowed external sharing ---
    scm = cal.get("secondary_calendar_max_allowed_external_sharing", {})
    if isinstance(scm, dict) and scm:
        sharing = (
            scm.get("maxAllowedExternalSharing", "")
            or scm.get("sharingLevel", "")
            or scm.get("accessLevel", "")
        )
        if sharing:
            _SHARING_MAP = {
                "FREE_BUSY_ONLY": "only_free_busy",
                "ONLY_FREE_BUSY": "only_free_busy",
                "ALL_INFORMATION": "all_information",
                "READ_WRITE_ACCESS": "read_write_access",
                "MANAGE_ACCESS": "read_write_access",
                "EXTERNAL_NO_FREE_BUSY": "no_sharing",
                "EXTERNAL_FREE_BUSY_ONLY": "only_free_busy",
                "EXTERNAL_ALL_INFO_READ_ONLY": "all_information",
                "EXTERNAL_ALL_INFO_READ_WRITE_MANAGE": "read_write_access",
            }
            sc = cal.setdefault("secondary_calendar", {})
            sc["external_sharing"] = _SHARING_MAP.get(sharing, sharing.lower())

    # --- Secondary calendar max allowed internal sharing ---
    scm_int = cal.get("secondary_calendar_max_allowed_internal_sharing", {})
    if isinstance(scm_int, dict) and scm_int:
        sharing = (
            scm_int.get("maxAllowedInternalSharing", "")
            or scm_int.get("sharingLevel", "")
            or scm_int.get("accessLevel", "")
        )
        if sharing:
            _INT_SHARING_MAP = {
                "FREE_BUSY_ONLY": "only_free_busy",
                "ONLY_FREE_BUSY": "only_free_busy",
                "ALL_INFORMATION": "all_information",
                "READ_WRITE_ACCESS": "read_write_access",
                "MANAGE_ACCESS": "read_write_access",
            }
            sc = cal.setdefault("secondary_calendar", {})
            sc["internal_sharing"] = _INT_SHARING_MAP.get(sharing, sharing.lower())

    # --- External invitations → external_invitation_warning ---
    ext_inv = cal.get("external_invitations", {})
    if isinstance(ext_inv, dict) and ext_inv:
        warn = ext_inv.get("warnOnInvite",
                           ext_inv.get("warnOnExternalInvitations", ext_inv.get("enabled")))
        if warn is not None:
            cal["external_invitation_warning"] = warn

    # --- Interoperability → interop ---
    interop_raw = cal.get("interoperability", {})
    if isinstance(interop_raw, dict) and interop_raw:
        enabled = interop_raw.get("enableInteroperability",
                                  interop_raw.get("enableInterop", interop_raw.get("enabled")))
        if enabled is not None:
            interop = cal.setdefault("interop", {})
            interop["exchange_interop_enabled"] = enabled
        auth = interop_raw.get("authenticationMethod", interop_raw.get("authMethod", ""))
        if auth:
            cal.setdefault("interop", {})["auth_method"] = auth.lower()

    # --- Calendar offline access ---
    offline = cal.get("calendar_offline_access", {})
    if isinstance(offline, dict) and offline:
        enabled = offline.get("enableOfflineAccess",
                              offline.get("enabled"))
        if enabled is not None:
            cal["offline_access_enabled"] = enabled

    # Flatten service_status dict to string
    ss = cal.get("service_status")
    if isinstance(ss, dict):
        state = ss.get("serviceState", "")
        if state:
            cal["service_status"] = state.lower()


def _map_chat(policies: dict) -> None:
    """Map Chat API settings to the nested keys Chat checks expect."""
    chat = policies.get("chat", {})
    if not chat or not isinstance(chat, dict):
        return

    # --- File sharing ---
    cfs = chat.get("chat_file_sharing", {})
    if isinstance(cfs, dict) and cfs:
        ext_fs = cfs.get("externalFileSharing", "")
        int_fs = cfs.get("internalFileSharing", "")
        fs = chat.setdefault("file_sharing", {})
        if ext_fs:
            fs["external_file_sharing_enabled"] = ext_fs != "NO_FILES"
        if int_fs:
            fs["internal_file_sharing_enabled"] = int_fs != "NO_FILES"

    # --- External spaces → spaces + external_chat ---
    ces = chat.get("chat_external_spaces", {})
    if isinstance(ces, dict) and ces:
        enabled = ces.get("enabled")
        if enabled is not None:
            chat.setdefault("spaces", {})["external_spaces_enabled"] = enabled
        mode = ces.get("domainAllowlistMode", "")
        if mode:
            restriction_map = {
                "ALL_DOMAINS": "unrestricted",
                "ALLOWLISTED_DOMAINS": "allowlisted_domains",
            }
            chat.setdefault("external_chat", {})["restriction_mode"] = (
                restriction_map.get(mode, mode.lower())
            )

    # --- Chat apps access → apps ---
    caa = chat.get("chat_apps_access", {})
    if isinstance(caa, dict) and caa:
        apps = chat.setdefault("apps", {})
        enable_apps = caa.get("enableApps")
        enable_wh = caa.get("enableWebhooks")
        if enable_apps is not None:
            apps["chat_apps_enabled"] = enable_apps
        if enable_wh is not None:
            apps["incoming_webhooks_enabled"] = enable_wh

    # --- Space history → history ---
    sh = chat.get("space_history", {})
    if isinstance(sh, dict) and sh:
        state = sh.get("historyState", "")
        if state:
            is_on = state in ("DEFAULT_HISTORY_ON", "ALWAYS_ON")
            hist = chat.setdefault("history", {})
            hist["history_on_by_default"] = is_on
            hist["history_enabled"] = is_on  # alias for CISA cisa_scuba
            hist["space_history_enabled"] = is_on  # alias for CISA cisa_services
            hist["history_state"] = state
            # CISA check_chat_history_user_control expects allow_user_modification
            hist["allow_user_modification"] = state != "ALWAYS_ON"

    # --- Content reporting ---
    cr = chat.get("chat_reporting", {})
    if isinstance(cr, dict) and cr:
        reporting = chat.setdefault("content_reporting", {})
        enabled = cr.get("contentReportingEnabled", cr.get("enabled"))
        if enabled is not None:
            reporting["enabled"] = enabled
        all_cats = cr.get("allCategoriesSelected")
        if all_cats is not None:
            reporting["all_categories_selected"] = all_cats

    # Flatten service_status dict to string
    ss = chat.get("service_status")
    if isinstance(ss, dict):
        state_val = ss.get("serviceState", "")
        if state_val:
            chat["service_status"] = state_val.lower()


def _map_meet(policies: dict) -> None:
    """Map Meet API settings to the nested keys Meet checks expect."""
    meet = policies.get("meet", {})
    if not meet or not isinstance(meet, dict):
        return

    # --- Joining controls (used by additional.py check_meet_joining_controls) ---
    joining = meet.get("meet_joining", {})
    if isinstance(joining, dict) and joining:
        audience = joining.get("allowedAudience", "")
        if audience:
            # TRUSTED = only org members can join without knocking
            # ALL = anyone can join
            must_ask = audience != "ALL"
            meet.setdefault("joining_controls", {})["knock_to_join_required"] = must_ask
            # Alias for CISA check_meet_external_join
            meet.setdefault("safety", {})["external_users_must_ask_to_join"] = must_ask

    # --- Safety domain ---
    sd = meet.get("safety_domain", {})
    if isinstance(sd, dict) and sd:
        allowed = sd.get("usersAllowedToJoin", "")
        if allowed:
            meet.setdefault("safety", {})["domain_restriction"] = allowed

    # --- Host management ---
    hm = meet.get("safety_host_management", {})
    if isinstance(hm, dict) and hm:
        enabled = hm.get("enableHostManagement")
        if enabled is not None:
            meet.setdefault("safety", {})["host_management_enabled"] = enabled

    # --- External participant labels → safety ---
    sep = meet.get("safety_external_participants", {})
    if isinstance(sep, dict) and sep:
        label = sep.get("enableExternalLabel")
        if label is not None:
            meet.setdefault("safety", {})["warn_for_external_participants"] = label

    # --- Safety access → safety ---
    sa = meet.get("safety_access", {})
    if isinstance(sa, dict) and sa:
        allowed = sa.get("meetingsAllowedToJoin", "")
        if allowed:
            meet.setdefault("safety", {})["non_workspace_meetings_allowed"] = (
                allowed == "ALL"
            )

    # --- Incoming call restrictions → calling ---
    icr = meet.get("meet_incoming_call_restrictions", {})
    if isinstance(icr, dict) and icr:
        callers = icr.get("allowedCallers", "")
        if callers:
            meet.setdefault("calling", {})["incoming_calls_restricted"] = (
                callers != "ANYONE"
            )

    # --- Recording ---
    rec = meet.get("video_recording", {})
    if isinstance(rec, dict) and rec:
        enabled = rec.get("enableRecording")
        if enabled is not None:
            recording = meet.setdefault("recording", {})
            recording["enabled"] = enabled
            # Alias for CISA check_meet_auto_recording: if recording is
            # disabled entirely, auto-recording is certainly disabled.
            recording.setdefault("auto_recording_enabled", enabled)

    # Flatten service_status dict to string
    ss = meet.get("service_status")
    if isinstance(ss, dict):
        state = ss.get("serviceState", "")
        if state:
            meet["service_status"] = state.lower()


def _map_sites(policies: dict) -> None:
    """Map Sites API settings to the flat keys Sites checks expect."""
    sites = policies.get("sites", {})
    if not sites or not isinstance(sites, dict):
        return

    scm = sites.get("sites_creation_and_modification", {})
    if isinstance(scm, dict) and scm:
        allow = scm.get("allowSitesCreation")
        if allow is not None:
            sites["sites_creation_enabled"] = allow

    # Flatten service_status dict to string for CISA check_sites_service_disabled
    ss = sites.get("service_status")
    if isinstance(ss, dict):
        state = ss.get("serviceState", "")
        if state:
            sites["service_status"] = state.lower()  # "enabled"/"disabled"


def _map_classroom(policies: dict) -> None:
    """Map Classroom API settings to the nested keys Classroom checks expect."""
    classroom = policies.get("classroom", {})
    if not classroom or not isinstance(classroom, dict):
        return

    # --- API data access → api_access ---
    ada = classroom.get("api_data_access", {})
    if isinstance(ada, dict) and ada:
        enabled = ada.get("enableApiAccess")
        if enabled is not None:
            classroom.setdefault("api_access", {})["enabled"] = enabled

    # --- Class membership → sharing ---
    cm = classroom.get("class_membership", {})
    if isinstance(cm, dict) and cm:
        sharing = classroom.setdefault("sharing", {})
        who_can_join = cm.get("whoCanJoinClasses", "")
        if who_can_join:
            sharing["class_membership"] = who_can_join
        which_classes = cm.get("whichClassesCanUsersJoin", "")
        if which_classes:
            sharing["classes_to_join"] = which_classes

    # --- Student unenrollment → class_settings ---
    su = classroom.get("student_unenrollment", {})
    if isinstance(su, dict) and su:
        who = su.get("whoCanUnenrollStudents", "")
        if who:
            classroom.setdefault("class_settings", {})["who_can_unenroll_students"] = who

    # --- Teacher permissions → class_settings ---
    tp = classroom.get("teacher_permissions", {})
    if isinstance(tp, dict) and tp:
        who = tp.get("whoCanCreateClasses", "")
        if who:
            classroom.setdefault("class_settings", {})["who_can_create_classes"] = who

    # --- Roster import ---
    ri = classroom.get("roster_import", {})
    if isinstance(ri, dict) and ri:
        option = ri.get("rosterImportOption", "")
        if option:
            # "CLEVER" or "SDS" = enabled; "OFF" = disabled
            classroom.setdefault("roster_import", {})["clever_enabled"] = (
                option.upper() == "CLEVER"
            )

    # Flatten service_status dict to string
    ss = classroom.get("service_status")
    if isinstance(ss, dict):
        state = ss.get("serviceState", "")
        if state:
            classroom["service_status"] = state.lower()


def _map_security(policies: dict) -> None:
    """Map Security API settings to the nested keys security checks expect."""
    security = policies.get("security", {})
    if not security or not isinstance(security, dict):
        return

    # --- Advanced Protection Program → advanced_protection ---
    app = security.get("advanced_protection_program", {})
    if isinstance(app, dict) and app:
        security.setdefault("advanced_protection", {})["enrollment_available"] = (
            app.get("enableAdvancedProtectionSelfEnrollment")
        )

    # --- Login challenges ---
    # The API key is already "login_challenges" so we add "enabled" to it.
    lc = security.get("login_challenges", {})
    if isinstance(lc, dict) and lc:
        # enableEmployeeIdChallenge = false means challenges are disabled
        lc["enabled"] = lc.get("enableEmployeeIdChallenge")

    # --- Super admin account recovery → account_recovery ---
    sar = security.get("super_admin_account_recovery", {})
    if isinstance(sar, dict) and sar:
        security.setdefault("account_recovery", {})["super_admin_recovery_enabled"] = (
            sar.get("enableAccountRecovery")
        )

    # --- Session controls → session_management ---
    sc = security.get("session_controls", {})
    if isinstance(sc, dict) and sc:
        duration_str = sc.get("webSessionDuration", "")
        if duration_str:
            seconds = _parse_duration_seconds(duration_str)
            hours = seconds / 3600 if seconds else 0
            sm = security.setdefault("session_management", {})
            sm["web_session_duration_hours"] = hours
            sm["session_duration_hours"] = hours  # alias for CISA CommonControls

    # --- Password → password_management ---
    pw = security.get("password", {})
    if isinstance(pw, dict) and pw:
        pm = security.setdefault("password_management", {})

        min_len = pw.get("minimumLength")
        if min_len is not None:
            pm["minimum_length"] = min_len

        enforce = pw.get("enforceRequirementsAtLogin")
        if enforce is not None:
            pm["enforce_strong_password"] = enforce

        strength = pw.get("allowedStrength", "")
        if strength:
            pm["strength"] = strength

        exp_str = pw.get("expirationDuration", "")
        if exp_str:
            exp_seconds = _parse_duration_seconds(exp_str)
            pm["expiration_days"] = exp_seconds // 86400 if exp_seconds else 0

    # --- Passkeys restriction → two_step_verification (partial) ---
    pkr = security.get("passkeys_restriction", {})
    if isinstance(pkr, dict) and pkr:
        passkey_type = pkr.get("allowedPasskeysType", "")
        if passkey_type:
            security.setdefault("passkeys", {})["allowed_type"] = passkey_type.lower()

    # --- User account recovery ---
    uar = security.get("user_account_recovery", {})
    if isinstance(uar, dict) and uar:
        ar = security.setdefault("account_recovery", {})
        enabled = uar.get("enableAccountRecovery", uar.get("enabled"))
        if enabled is not None:
            ar["user_recovery_enabled"] = enabled
        allow_info = uar.get("allowRecoveryInfo", uar.get("allowPersonalRecoveryInfo"))
        if allow_info is not None:
            ar["allow_recovery_info"] = allow_info

    # --- Less secure apps ---
    lsa = security.get("less_secure_apps", {})
    if isinstance(lsa, dict) and lsa:
        allowed = lsa.get("allowLessSecureApps", lsa.get("enabled", lsa.get("allowed")))
        if allowed is not None:
            security.setdefault("less_secure_apps", {})["allowed"] = allowed

    # --- 2SV enrollment ---
    tsv_enroll = security.get("two_step_verification_enrollment", {})
    if isinstance(tsv_enroll, dict) and tsv_enroll:
        tsv = security.setdefault("two_step_verification", {})
        enabled = tsv_enroll.get("allowEnrollment",
                                 tsv_enroll.get("enableEnrollment", tsv_enroll.get("enabled")))
        if enabled is not None:
            tsv["enrollment_enabled"] = enabled
        days = tsv_enroll.get("newUserEnrollmentPeriodDays",
                              tsv_enroll.get("new_user_enrollment_period_days"))
        if days is not None:
            try:
                tsv["new_user_enrollment_period_days"] = int(days)
            except (ValueError, TypeError):
                tsv["new_user_enrollment_period_days"] = days

    # --- 2SV enforcement ---
    tsv_enforce = security.get("two_step_verification_enforcement", {})
    if isinstance(tsv_enforce, dict) and tsv_enforce:
        tsv = security.setdefault("two_step_verification", {})
        # The API may use enforcedFrom (non-empty string = enforced) or
        # enableEnforcement (boolean).
        enforced_from = tsv_enforce.get("enforcedFrom")
        if enforced_from is not None:
            # enforcedFrom is a date string; non-empty means enforcement is on
            enforced = bool(enforced_from)
        else:
            enforced = tsv_enforce.get("enableEnforcement", tsv_enforce.get("enforced"))
        if enforced is not None:
            tsv["enforcement"] = enforced
            tsv["admin_enforcement"] = enforced

    # --- 2SV enforcement factor (allowed methods) ---
    tsv_factor = security.get("two_step_verification_enforcement_factor", {})
    if isinstance(tsv_factor, dict) and tsv_factor:
        method = (
            tsv_factor.get("allowedSignInFactorSet", "")
            or tsv_factor.get("allowedMethod", "")
            or tsv_factor.get("enforcementFactor", "")
            or tsv_factor.get("allowedType", "")
        )
        if method:
            tsv = security.setdefault("two_step_verification", {})
            tsv["admin_allowed_methods"] = method.lower()

    # --- 2SV device trust ---
    tsv_trust = security.get("two_step_verification_device_trust", {})
    if isinstance(tsv_trust, dict) and tsv_trust:
        enabled = tsv_trust.get("allowTrustingDevice",
                                tsv_trust.get("enableDeviceTrust", tsv_trust.get("enabled")))
        if enabled is not None:
            security.setdefault("two_step_verification", {})["device_trust_enabled"] = enabled

    # --- Passkeys → authentication.passkeys_enforced ---
    passkeys = security.get("passkeys", {})
    allowed = passkeys.get("allowed_type", "")
    if allowed:
        authn = security.setdefault("authentication", {})
        authn["passkeys_enforced"] = allowed == "security_key_only"


def _map_data_regions(policies: dict) -> None:
    """Map data_regions policy category into security.data_regions.

    CISA checks ``GWS.COMMONCONTROLS.15.1`` and ``15.2`` look for
    ``policies["security"]["data_regions"]`` but the Cloud Identity
    Policy API returns data regions as a separate ``data_regions``
    category.  This function bridges the gap.
    """
    dr = policies.get("data_regions", {})
    if not dr or not isinstance(dr, dict):
        return

    security = policies.setdefault("security", {})
    dr_out: dict = {}

    # Check if any data region settings are configured
    # The API may return various keys depending on the tenant's edition.
    dr_out["configured"] = bool(dr)

    # Map known data-region fields
    for key in ("data_at_rest_region", "data_processing_region",
                "processing_in_region"):
        val = dr.get(key)
        if val is not None:
            dr_out[key] = val

    # Derive processing_in_region from data_processing_region.limitToStorageRegion
    # (the Policy API exposes the toggle under the nested data_processing_region
    # payload, but checks expect a flat boolean on security.data_regions).
    dpr = dr.get("data_processing_region")
    if isinstance(dpr, dict):
        limit = dpr.get("limitToStorageRegion", dpr.get("limit_to_storage_region"))
        if limit is not None:
            dr_out["processing_in_region"] = bool(limit)

    # If data_regions has _ou_policies, propagate them so that
    # get_ou_values(security, "data_regions") finds per-OU data.
    ou_policies = dr.get("_ou_policies")
    if ou_policies:
        security.setdefault("_ou_policies", []).extend(ou_policies)
    ou_map = dr.get("_ou_id_map")
    if ou_map:
        security.setdefault("_ou_id_map", {}).update(ou_map)

    security["data_regions"] = dr_out


def _map_api_controls_to_security(policies: dict) -> None:
    """Map API Controls settings to security.api_access and security.app_access.

    CIS checks use ``security.api_access.*`` while CISA CommonControls
    checks use ``security.app_access.*``.  We populate both.
    """
    ac = policies.get("api_controls", {})
    if not ac or not isinstance(ac, dict):
        return

    security = policies.setdefault("security", {})
    api_access = security.setdefault("api_access", {})
    app_access = security.setdefault("app_access", {})  # alias for CISA checks

    # --- Unconfigured third-party apps → trust policy ---
    uta = ac.get("unconfigured_third_party_apps", {})
    if isinstance(uta, dict) and uta:
        level = uta.get("accessLevel", "")
        if level:
            # UNSPECIFIED_UBER_BLOCK = restricted, UNSPECIFIED_UBER_ALLOW = unrestricted
            is_restricted = "BLOCK" in level.upper()
            api_access["third_party_apps_restricted"] = is_restricted
            api_access["trust_policy"] = "restricted" if is_restricted else "unrestricted"
            # CISA CommonControls aliases
            app_access["third_party_api_access_restricted"] = is_restricted
            app_access["allow_unconfigured_third_party_apps"] = not is_restricted

    # --- Internal apps ---
    ia = ac.get("internal_apps", {})
    if isinstance(ia, dict) and ia:
        trust = ia.get("trustInternalApps")
        if trust is not None:
            api_access["internal_apps_controlled"] = not trust
            # CISA CommonControls alias
            app_access["trust_unconfigured_internal_apps"] = trust


def _map_groups(policies: dict) -> None:
    """Map Groups API settings to the nested keys Groups checks expect."""
    groups = policies.get("groups", {})
    if not groups or not isinstance(groups, dict):
        return

    # --- Groups sharing → external members, creation, visibility ---
    gs = groups.get("groups_sharing", {})
    if isinstance(gs, dict) and gs:
        # The API may use collaborationCapability instead of allowExternalMembers.
        # FULL_COLLABORATION = external members allowed
        collab = gs.get("collaborationCapability", "")
        ext = gs.get("allowExternalMembers", gs.get("externalMembersAllowed"))
        if ext is None and collab:
            ext = collab.upper() == "FULL_COLLABORATION"
        if ext is not None:
            groups["external_members_allowed"] = ext
            groups.setdefault("sharing", {})["allow_external_members"] = ext
        ext_access = gs.get("externalAccessDefault", gs.get("defaultExternalAccess", ""))
        if ext_access:
            groups.setdefault("sharing", {})["external_access_default"] = ext_access.lower()
        creator = (
            gs.get("whoCanCreateGroups", "")
            or gs.get("groupCreation", "")
            or gs.get("whoCanCreate", "")
        )
        if creator:
            # Normalize API enum to consistent lowercase form
            _CREATOR_MAP = {
                "ALL_USERS_CAN_CREATE": "all_users_in_domain",
                "ADMINS_CAN_CREATE": "admins_only",
            }
            normalized_creator = _CREATOR_MAP.get(creator, creator.lower())
            groups["who_can_create_groups"] = normalized_creator
            groups.setdefault("creation", {})["who_can_create"] = normalized_creator
        vis = (
            gs.get("defaultMessageVisibility", "")
            or gs.get("conversationVisibility", "")
            or gs.get("defaultConversationVisibility", "")
        )
        if vis:
            groups["default_message_visibility"] = vis.lower()
            groups.setdefault("visibility", {})["default_conversation_visibility"] = vis.lower()
        ext_post = gs.get("allowExternalPosting", gs.get("externalPostingAllowed"))
        if ext_post is not None:
            groups["allow_external_posting"] = ext_post
        ext_groups = gs.get("externalGroupsAccessEnabled", gs.get("allowExternalGroupsAccess"))
        if ext_groups is not None:
            groups["external_groups_access_enabled"] = ext_groups
        hide = gs.get("allowHidingFromDirectory", gs.get("hideFromDirectory"))
        if hide is not None:
            groups["allow_hiding_from_directory"] = hide

        # Owner-controlled toggles (CIS-3.1.6.3, GWS.GROUPS.4.1)
        owner_incoming = gs.get(
            "ownersCanAllowIncomingMailFromPublic",
            gs.get("ownersCanAllowIncomingMail"),
        )
        if owner_incoming is not None:
            groups["owners_can_allow_incoming_mail_from_public"] = owner_incoming
        owner_hide = gs.get("ownersCanHideGroups")
        if owner_hide is not None:
            groups["owners_can_hide_groups"] = owner_hide
        new_hidden = gs.get("newGroupsAreHidden")
        if new_hidden is not None:
            groups["new_groups_are_hidden"] = new_hidden
        topic_view = gs.get("viewTopicsDefaultAccessLevel")
        if topic_view:
            normalized_view = topic_view.lower()
            groups["view_topics_default_access_level"] = normalized_view
            # Also surface as default_message_visibility when not already set
            # so legacy CIS-3.1.6.3 logic can resolve it.
            if not groups.get("default_message_visibility"):
                _VIEW_MAP = {
                    "group_members": "members_only",
                    "managers_only": "private",
                    "owners_only": "private",
                    "anyone_can_view_topics": "public",
                    "all_in_domain_can_view": "domain",
                }
                groups["default_message_visibility"] = _VIEW_MAP.get(
                    normalized_view, normalized_view,
                )

    # Flatten service_status dict to string
    ss = groups.get("service_status")
    if isinstance(ss, dict):
        state = ss.get("serviceState", "")
        if state:
            groups["service_status"] = state.lower()


def _map_marketplace(policies: dict) -> None:
    """Map Marketplace API settings to the nested keys Marketplace checks expect."""
    mp = policies.get("marketplace", {})
    if not mp or not isinstance(mp, dict):
        return

    # --- Apps access options → app_install_policy ---
    aao = mp.get("apps_access_options", {})
    if isinstance(aao, dict) and aao:
        policy = (
            aao.get("accessLevel", "")
            or aao.get("appInstallPolicy", "")
            or aao.get("installPolicy", "")
            or aao.get("accessOption", "")
        )
        if policy:
            mp["app_install_policy"] = policy.lower()
            mp["restrict_to_approved_apps"] = "allowlist" in policy.lower() or "approved" in policy.lower()

    # --- Apps allowlist → restrict_to_approved_apps ---
    al = mp.get("apps_allowlist", {})
    if isinstance(al, dict) and al:
        apps = al.get("allowlistedApps", al.get("apps", []))
        if isinstance(apps, list):
            mp["allowlisted_apps"] = apps
            if apps:
                mp.setdefault("restrict_to_approved_apps", True)

    # Flatten service_status dict to string
    ss = mp.get("service_status")
    if isinstance(ss, dict):
        state = ss.get("serviceState", "")
        if state:
            mp["service_status"] = state.lower()


def _map_directory(policies: dict) -> None:
    """Map Directory API settings to the nested keys Directory checks expect."""
    directory = policies.get("directory", {})
    if not directory or not isinstance(directory, dict):
        return

    # --- External directory sharing ---
    eds = directory.get("external_directory_sharing", {})
    if isinstance(eds, dict) and eds:
        # The Cloud Identity Policy API returns sharing_option with enum:
        #   REQUESTER_BASIC_PROFILE_ONLY = restricted (PASS)
        #   ORGANIZATION_DIRECTORY_DATA  = not restricted (FAIL)
        sharing_option = eds.get("sharing_option", "")
        if sharing_option:
            is_restricted = sharing_option == "REQUESTER_BASIC_PROFILE_ONLY"
            directory.setdefault("sharing_settings", {})["external_sharing_restricted"] = is_restricted
        # Legacy / alternate field names
        restricted = eds.get("restrictExternalSharing", eds.get("externalSharingRestricted"))
        if restricted is not None:
            directory.setdefault("sharing_settings", {})["external_sharing_restricted"] = restricted
        # Also check the inverse
        allowed = eds.get("allowExternalSharing", eds.get("externalSharingAllowed"))
        if allowed is not None:
            directory.setdefault("sharing_settings", {})["external_sharing_restricted"] = not allowed

    # Flatten service_status dict to string
    ss = directory.get("service_status")
    if isinstance(ss, dict):
        state = ss.get("serviceState", "")
        if state:
            directory["service_status"] = state.lower()


def _map_chrome_policies(policies: dict, chrome_policies: dict) -> None:
    """Map Chrome Policy API data into the policies dict for checks.

    Chrome policies are resolved separately from Cloud Identity policies.
    This function maps the Chrome-specific settings into the nested
    structure that existing checks expect.

    Parameters
    ----------
    policies:
        The main policies dict (mutated in place).
    chrome_policies:
        The dict returned by ``ChromePolicyClient.get_chrome_policies()``.
    """
    if not chrome_policies or not isinstance(chrome_policies, dict):
        return

    # Gemini in Chrome → gemini.chrome.enabled (inverted: disabled → not enabled)
    if "gemini_in_chrome_disabled" in chrome_policies:
        gemini = policies.setdefault("gemini", {})
        chrome = gemini.setdefault("chrome", {})
        chrome["enabled"] = not chrome_policies["gemini_in_chrome_disabled"]

    # DBSC → security.session_management.dbsc_enabled
    if "dbsc_enabled" in chrome_policies:
        security = policies.setdefault("security", {})
        sm = security.setdefault("session_management", {})
        sm["dbsc_enabled"] = chrome_policies["dbsc_enabled"]

    # Password Protection → security.password_alert
    if "password_protection_warning_trigger" in chrome_policies:
        security = policies.setdefault("security", {})
        pa = security.setdefault("password_alert", {})
        trigger = chrome_policies["password_protection_warning_trigger"]
        # 0 = off, 1 = password reuse warning, 2 = phishing + reuse warning
        pa["deployed"] = trigger > 0
        pa["trigger"] = trigger


def _map_multi_party_approval(policies: dict) -> None:
    """Map Multi-Party Approval policy data to security.multi_party_approval.

    The Cloud Identity Policy API returns multi_party_approval as a
    category with settings like ``require_approvals`` and
    ``security_actions``.  This function maps them to the nested keys
    that check functions expect.
    """
    mpa_raw = policies.get("multi_party_approval", {})
    if not mpa_raw or not isinstance(mpa_raw, dict):
        return

    security = policies.setdefault("security", {})
    mpa = security.setdefault("multi_party_approval", {})

    # require_approvals → enabled
    ra = mpa_raw.get("require_approvals", {})
    if isinstance(ra, dict) and ra:
        mpa["enabled"] = ra.get(
            "enableMultiPartyApproval", ra.get("enabled", False)
        )

    # security_actions may list covered actions — check for vault
    sa = mpa_raw.get("security_actions", {})
    if isinstance(sa, dict) and sa:
        covered = sa.get("coveredActions", sa.get("actions", []))
        if isinstance(covered, list):
            mpa["vault_exports_covered"] = any(
                "vault" in str(a).lower() for a in covered
            )


def _map_rules(policies: dict) -> None:
    """Map DLP rules from the rules policy category to security.dlp.

    The Cloud Identity Policy API ``rules`` category (setting type
    prefix ``rule``) contains DLP rules.  This function scans them for
    Calendar-targeted rules and populates ``security.dlp.calendar_dlp_*``.
    """
    rules = policies.get("rules", {})
    if not rules or not isinstance(rules, dict):
        return

    security = policies.setdefault("security", {})
    dlp = security.setdefault("dlp", {})

    calendar_rules = []
    for key, rule_data in rules.items():
        if not isinstance(rule_data, dict):
            continue
        # Look for trigger apps or target apps containing calendar
        triggers = rule_data.get(
            "triggers", rule_data.get("triggerApps", [])
        )
        if isinstance(triggers, list):
            for t in triggers:
                app = (
                    t.get("app", t.get("application", ""))
                    if isinstance(t, dict)
                    else str(t)
                )
                if "calendar" in str(app).lower():
                    calendar_rules.append(rule_data)
                    break

    if calendar_rules:
        dlp["calendar_dlp_rules"] = calendar_rules
        dlp["calendar_dlp_enabled"] = True


def _normalize_activity_logs(logs: list) -> list:
    """Flatten nested activity log events for easier check consumption.

    The Admin SDK Reports API returns logs with nested "events" arrays.
    Checks expect flat entries with "event_name" and "parameters" fields.
    Each event within a log entry becomes its own flattened entry.
    """
    if not logs:
        return []

    normalized = []
    for log in logs:
        if not isinstance(log, dict):
            normalized.append(log)
            continue

        events = log.get("events", [])
        actor = log.get("actor", {})

        # If already flattened (has event_name), keep as-is
        if "event_name" in log or not events:
            if "event_name" not in log:
                # No events and no event_name — preserve the log entry
                # with minimal normalization
                log.setdefault("event_name", "")
                log.setdefault("event_type", "")
                log.setdefault("parameters", {})
                log.setdefault("actor_email", actor.get("email", ""))
            normalized.append(log)
            continue

        # Flatten: one log entry per event
        for event in events:
            if not isinstance(event, dict):
                continue
            entry = {
                "actor_email": actor.get("email", ""),
                "event_name": event.get("name", ""),
                "event_type": event.get("type", ""),
                "time": log.get("id", {}).get("time", "") if isinstance(log.get("id"), dict) else "",
                "ip_address": log.get("ipAddress", ""),
            }
            # Convert parameters list to dict for easy access
            params = {}
            for param in event.get("parameters", []):
                if not isinstance(param, dict):
                    continue
                param_name = param.get("name", "")
                if "value" in param:
                    params[param_name] = param["value"]
                elif "multiValue" in param:
                    params[param_name] = param["multiValue"]
                elif "boolValue" in param:
                    params[param_name] = param["boolValue"]
                elif "intValue" in param:
                    params[param_name] = param["intValue"]
                else:
                    params[param_name] = param.get("multiMessageValue", "")
            entry["parameters"] = params
            # Promote common parameter values to top-level for easy access
            # (some checks reference log.get("app_name") directly)
            for key in ("app_name", "client_id", "client_type",
                        "scope", "alert_name"):
                if key in params and key not in entry:
                    entry[key] = params[key]
            normalized.append(entry)

    return normalized


def _normalize_dns_records(dns_records: dict) -> dict:
    """Add check-expected field aliases to DNS data.

    The DNS client uses ``"exists"`` boolean fields, but checks look for
    ``"record_found"``.  The MX data is returned as a dict with a nested
    ``"records"`` list, but checks iterate over ``domain_dns["mx"]``
    expecting a flat list of ``{host, priority}`` dicts.

    This function adds aliases and flattens the MX structure so checks
    work without modification.
    """
    if not isinstance(dns_records, dict):
        return {}

    normalized = {}
    for domain, data in dns_records.items():
        if not isinstance(data, dict):
            normalized[domain] = data
            continue

        norm = dict(data)  # shallow copy

        # Add record_found alias for exists in SPF/DKIM/DMARC
        for key in ("spf", "dkim", "dmarc"):
            sub = norm.get(key, {})
            if isinstance(sub, dict) and "record_found" not in sub:
                sub["record_found"] = sub.get("exists", False)

        # Flatten MX: checks expect domain_dns["mx"] to be a list of
        # {host, priority} records, not a dict wrapping them.
        mx = norm.get("mx", {})
        if isinstance(mx, dict):
            norm["mx_uses_google"] = mx.get("uses_google", False)
            norm["mx"] = mx.get("records", [])

        normalized[domain] = norm

    return normalized
