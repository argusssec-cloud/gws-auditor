"""Tests for DNS lookup helpers (DKIM multi-selector, DMARC org-domain fallback)."""

from unittest.mock import MagicMock, patch

import dns.resolver

from gws_auditor.api.dns import DNSClient


class _FakeRdata:
    def __init__(self, txt: str):
        self._txt = txt

    def to_text(self):
        # dnspython quotes TXT records; strip handled by DNSClient.
        return f'"{self._txt}"'


def _make_client():
    return DNSClient(auth_manager=None)


class TestDKIMMultiSelector:
    def test_default_selectors_first_match_wins(self):
        client = _make_client()

        def fake_resolve(qname, rdtype):
            if qname == "google._domainkey.example.com":
                return [_FakeRdata("v=DKIM1; k=rsa; p=BASE64KEY")]
            raise dns.resolver.NoAnswer()

        with patch.object(client._resolver, "resolve", side_effect=fake_resolve):
            result = client.check_dkim("example.com")

        assert result["exists"] is True
        assert result["selector"] == "google"
        assert result["selectors_tried"] == ["google"]
        assert "p=" in result["record"]

    def test_falls_through_to_second_selector(self):
        client = _make_client()

        def fake_resolve(qname, rdtype):
            if qname == "google2025._domainkey.example.com":
                return [_FakeRdata("v=DKIM1; p=KEY2025")]
            raise dns.resolver.NoAnswer()

        with patch.object(client._resolver, "resolve", side_effect=fake_resolve):
            result = client.check_dkim("example.com")

        assert result["exists"] is True
        assert result["selector"] == "google2025"
        assert result["selectors_tried"][:2] == ["google", "google2025"]

    def test_no_selector_matches_returns_not_exists(self):
        client = _make_client()
        with patch.object(
            client._resolver,
            "resolve",
            side_effect=dns.resolver.NoAnswer(),
        ):
            result = client.check_dkim("example.com")
        assert result["exists"] is False
        assert result["record"] == ""
        # All defaults attempted.
        assert len(result["selectors_tried"]) >= 5

    def test_explicit_selector_overrides_default_list(self):
        client = _make_client()

        def fake_resolve(qname, rdtype):
            if qname == "custom._domainkey.example.com":
                return [_FakeRdata("v=DKIM1; p=CUSTOMKEY")]
            raise dns.resolver.NoAnswer()

        with patch.object(client._resolver, "resolve", side_effect=fake_resolve):
            result = client.check_dkim("example.com", selector="custom")

        assert result["exists"] is True
        assert result["selectors_tried"] == ["custom"]

    def test_explicit_selectors_list(self):
        client = _make_client()

        def fake_resolve(qname, rdtype):
            if qname == "k1._domainkey.example.com":
                return [_FakeRdata("v=DKIM1; p=K1")]
            raise dns.resolver.NoAnswer()

        with patch.object(client._resolver, "resolve", side_effect=fake_resolve):
            result = client.check_dkim(
                "example.com", selectors=["mail", "k1", "k2"]
            )

        assert result["exists"] is True
        assert result["selector"] == "k1"
        assert result["selectors_tried"] == ["mail", "k1"]


class TestDMARCOrgDomainFallback:
    def test_record_at_subdomain_no_fallback(self):
        client = _make_client()

        def fake_resolve(qname, rdtype):
            if qname == "_dmarc.mail.example.com":
                return [_FakeRdata("v=DMARC1; p=reject; sp=quarantine")]
            raise dns.resolver.NoAnswer()

        with patch.object(client._resolver, "resolve", side_effect=fake_resolve):
            result = client.check_dmarc("mail.example.com")

        assert result["exists"] is True
        assert result["policy"] == "reject"
        assert result["subdomain_policy"] == "quarantine"
        assert result["inherited_from"] == ""

    def test_falls_back_to_org_domain(self):
        client = _make_client()

        def fake_resolve(qname, rdtype):
            if qname == "_dmarc.example.com":
                return [_FakeRdata("v=DMARC1; p=reject")]
            raise dns.resolver.NoAnswer()

        with patch.object(client._resolver, "resolve", side_effect=fake_resolve):
            result = client.check_dmarc("mail.example.com")

        assert result["exists"] is True
        assert result["policy"] == "reject"
        # No explicit sp= → defaults to policy per RFC 7489 inheritance.
        assert result["subdomain_policy"] == "reject"
        assert result["inherited_from"] == "example.com"

    def test_no_record_anywhere(self):
        client = _make_client()
        with patch.object(
            client._resolver,
            "resolve",
            side_effect=dns.resolver.NoAnswer(),
        ):
            result = client.check_dmarc("mail.example.com")
        assert result["exists"] is False
        assert result["policy"] == ""
        assert result["inherited_from"] == ""

    def test_subdomain_policy_explicit(self):
        client = _make_client()

        def fake_resolve(qname, rdtype):
            if qname == "_dmarc.example.com":
                return [_FakeRdata("v=DMARC1; p=reject; sp=none")]
            raise dns.resolver.NoAnswer()

        with patch.object(client._resolver, "resolve", side_effect=fake_resolve):
            result = client.check_dmarc("example.com")

        assert result["policy"] == "reject"
        assert result["subdomain_policy"] == "none"
