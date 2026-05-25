"""Tests for Provider subscription/edition detection."""

from collections import Counter
from unittest.mock import MagicMock, patch

import pytest

from gws_auditor.provider import Provider


class TestResolveEdition:
    """Tests for Provider._resolve_edition SKU mapping.

    SKU IDs are per Google's authoritative Admin SDK Licensing reference:
    https://developers.google.com/workspace/admin/licensing/v1/how-tos/products
    """

    def test_enterprise_standard_sku(self):
        label, tier = Provider._resolve_edition("1010020026")
        assert label == "Google Workspace Enterprise Standard"
        assert tier == "enterprise_standard"

    def test_enterprise_plus_sku(self):
        label, tier = Provider._resolve_edition("1010020020")
        assert label == "Google Workspace Enterprise Plus"
        assert tier == "enterprise_plus"

    def test_frontline_standard_sku(self):
        label, tier = Provider._resolve_edition("1010020031")
        assert label == "Google Workspace Frontline Standard"
        assert tier == "frontline_standard"

    def test_business_plus_sku(self):
        label, tier = Provider._resolve_edition("1010020025")
        assert label == "Google Workspace Business Plus"
        assert tier == "business_plus"

    def test_business_starter_sku(self):
        label, tier = Provider._resolve_edition("1010020027")
        assert label == "Google Workspace Business Starter"
        assert tier == "business_starter"

    def test_enterprise_essentials_sku(self):
        label, tier = Provider._resolve_edition("1010060003")
        assert label == "Google Workspace Enterprise Essentials"
        assert tier == "enterprise_essentials"

    def test_legacy_g_suite_sku(self):
        label, tier = Provider._resolve_edition("Google-Apps-For-Business")
        assert "Legacy" in label
        assert tier == "business_standard"

    def test_unknown_sku(self):
        label, tier = Provider._resolve_edition("9999999999")
        assert label == "Unknown (SKU: 9999999999)"
        assert tier == ""


class TestPickPrimaryEdition:
    """Tests for Provider._pick_primary_edition tier selection."""

    def test_empty_counter(self):
        edition, tier = Provider._pick_primary_edition(Counter())
        assert edition == ""
        assert tier == ""

    def test_single_enterprise_standard(self):
        edition, tier = Provider._pick_primary_edition(
            Counter({"1010020026": 482})
        )
        assert edition == "Google Workspace Enterprise Standard"
        assert tier == "enterprise_standard"

    def test_mixed_enterprise_and_frontline_picks_enterprise(self):
        """Tenant with majority Frontline + some Enterprise → Enterprise wins.

        Regression: previously maxResults=1 could surface Frontline first.
        """
        counts = Counter({
            "1010020031": 950,   # Frontline Standard (more users)
            "1010020026": 50,    # Enterprise Standard
        })
        edition, tier = Provider._pick_primary_edition(counts)
        assert edition == "Google Workspace Enterprise Standard"
        assert tier == "enterprise_standard"

    def test_mixed_enterprise_plus_beats_enterprise_standard(self):
        counts = Counter({
            "1010020026": 1000,   # Enterprise Standard
            "1010020020": 5,      # Enterprise Plus
        })
        edition, tier = Provider._pick_primary_edition(counts)
        assert edition == "Google Workspace Enterprise Plus"
        assert tier == "enterprise_plus"

    def test_only_legacy_sku(self):
        edition, tier = Provider._pick_primary_edition(
            Counter({"Google-Apps-Unlimited": 100})
        )
        assert "Business Plus (Legacy)" in edition
        assert tier == "business_plus"

    def test_only_cloud_identity_returns_empty(self):
        """Cloud Identity is not a Workspace edition — should not win."""
        edition, tier = Provider._pick_primary_edition(
            Counter({"1010050001": 200})
        )
        assert edition == ""
        assert tier == ""

    def test_mixed_workspace_and_cloud_identity_picks_workspace(self):
        counts = Counter({
            "1010050001": 500,    # Cloud Identity Premium
            "1010020028": 20,     # Business Standard
        })
        edition, tier = Provider._pick_primary_edition(counts)
        assert edition == "Google Workspace Business Standard"
        assert tier == "business_standard"

    def test_unknown_sku_with_workspace_picks_workspace(self):
        counts = Counter({
            "9999999999": 999,
            "1010020028": 1,      # Business Standard
        })
        edition, tier = Provider._pick_primary_edition(counts)
        assert edition == "Google Workspace Business Standard"
        assert tier == "business_standard"

    def test_zero_count_sku_ignored(self):
        edition, _ = Provider._pick_primary_edition(
            Counter({"1010020020": 0, "1010020028": 5})  # Enterprise Plus 0, Business Standard 5
        )
        assert edition == "Google Workspace Business Standard"


class TestGetSubscriptionInfo:
    """Tests for Provider._get_subscription_info — paginated aggregation."""

    def _make_provider(self):
        prov = Provider.__new__(Provider)
        prov.auth = MagicMock()
        prov.customer_id = "C12345"
        return prov

    def test_paginates_across_pages(self):
        """All pages of license assignments are consumed."""
        prov = self._make_provider()

        pages = {
            "Google-Apps": [
                ({"items": [{"skuId": "1010020026"}] * 500,   # Enterprise Standard
                  "nextPageToken": "p2"}),
                ({"items": [{"skuId": "1010020026"}] * 200,
                  "nextPageToken": None}),
            ],
            "Google-Apps-For-Education": [
                ({"items": [], "nextPageToken": None}),
            ],
        }

        # Build a service mock whose listForProduct returns a request whose
        # execute() pops the next page for the requested product.
        page_state = {pid: list(p) for pid, p in pages.items()}

        def make_request(productId, customerId, maxResults, pageToken):
            request = MagicMock()
            request.execute.side_effect = lambda: page_state[productId].pop(0)
            return request

        service = MagicMock()
        service.licenseAssignments().listForProduct.side_effect = make_request
        prov.auth.build_service.return_value = service
        # Provider also checks for _execute_request — make hasattr return False
        del prov.auth._execute_request

        info = prov._get_subscription_info()

        assert info["edition"] == "Google Workspace Enterprise Standard"
        assert info["tier_key"] == "enterprise_standard"
        assert len(info["skus"]) == 1
        assert info["skus"][0]["sku_id"] == "1010020026"
        assert info["skus"][0]["count"] == 700

    def test_mixed_skus_breakdown_reported(self):
        """The per-SKU breakdown lists all SKUs sorted by count desc."""
        prov = self._make_provider()

        responses = {
            "Google-Apps": {
                "items": (
                    [{"skuId": "1010020031"}] * 950   # Frontline Standard (more users)
                    + [{"skuId": "1010020026"}] * 50  # Enterprise Standard
                ),
                "nextPageToken": None,
            },
            "Google-Apps-For-Education": {
                "items": [],
                "nextPageToken": None,
            },
        }

        service = MagicMock()
        request = MagicMock()
        request.execute.side_effect = lambda: responses[
            service.licenseAssignments().listForProduct.call_args.kwargs[
                "productId"
            ]
        ]
        service.licenseAssignments().listForProduct.return_value = request
        prov.auth.build_service.return_value = service
        del prov.auth._execute_request

        info = prov._get_subscription_info()

        # Highest tier wins despite Frontline being more common.
        assert info["edition"] == "Google Workspace Enterprise Standard"
        # Breakdown sorted by count: Frontline first, Enterprise second.
        sku_ids = [s["sku_id"] for s in info["skus"]]
        assert sku_ids == ["1010020031", "1010020026"]
        assert info["skus"][0]["count"] == 950
        assert info["skus"][1]["count"] == 50
        # tier_keys_present surfaces all distinct tiers for advisory checks.
        assert info["tier_keys_present"] == [
            "enterprise_standard", "frontline_standard",
        ]
        assert info["source"] == "licensing"

    def test_api_unavailable_returns_empty(self):
        """When the Licensing API errors out, returns empty edition gracefully."""
        prov = self._make_provider()
        prov.auth.build_service.side_effect = Exception("API not enabled")

        info = prov._get_subscription_info()

        assert info["edition"] == ""
        assert info["tier_key"] == ""
        assert info["skus"] == []
        assert info["tier_keys_present"] == []
        assert info["source"] == ""

    def test_education_product_consulted(self):
        """Education-only tenant is detected via Google-Apps-For-Education."""
        prov = self._make_provider()

        per_product = {
            "Google-Apps": {"items": [], "nextPageToken": None},
            "Google-Apps-For-Education": {
                "items": [{"skuId": "1010310003"}] * 10,
                "nextPageToken": None,
            },
        }

        service = MagicMock()
        request = MagicMock()
        request.execute.side_effect = lambda: per_product[
            service.licenseAssignments().listForProduct.call_args.kwargs[
                "productId"
            ]
        ]
        service.licenseAssignments().listForProduct.return_value = request
        prov.auth.build_service.return_value = service
        del prov.auth._execute_request

        info = prov._get_subscription_info()

        assert info["edition"] == "Google Workspace for Education Plus"
        assert info["tier_key"] == "education_plus"
