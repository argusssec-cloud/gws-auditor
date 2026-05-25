# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""DNS lookup client for email authentication records.

Uses the ``dnspython`` library to query SPF, DKIM, DMARC, and MX records
for domains under audit.  These checks do not require Google API
credentials -- they query public DNS.
"""

import logging
import re
from typing import Any

import dns.resolver
import dns.exception

from .base import BaseAPIClient

logger = logging.getLogger(__name__)

# Common Google MX hosts (lowercase).
_GOOGLE_MX_HOSTS = {
    "aspmx.l.google.com",
    "alt1.aspmx.l.google.com",
    "alt2.aspmx.l.google.com",
    "alt3.aspmx.l.google.com",
    "alt4.aspmx.l.google.com",
    "aspmx2.googlemail.com",
    "aspmx3.googlemail.com",
    "aspmx4.googlemail.com",
    "aspmx5.googlemail.com",
    "smtp.google.com",
    "smtp-in.l.google.com",
}


class DNSClient(BaseAPIClient):
    """DNS lookup client for email authentication record verification.

    Unlike the other API clients, this class does not use Google API
    credentials.  It inherits from :class:`BaseAPIClient` to share the
    error-collection interface.

    Parameters
    ----------
    auth_manager:
        Accepted for interface consistency but not used for DNS queries.
    nameservers:
        Optional list of DNS resolver addresses.  When ``None``, the
        system default resolvers are used.
    timeout:
        Per-query timeout in seconds.
    """

    def __init__(
        self,
        auth_manager=None,
        nameservers: list[str] | None = None,
        timeout: float = 10.0,
        **kwargs,
    ):
        super().__init__(auth_manager or _NullAuth(), **kwargs)
        self._resolver = dns.resolver.Resolver()
        if nameservers:
            self._resolver.nameservers = nameservers
        self._resolver.lifetime = timeout

    # ------------------------------------------------------------------
    # SPF
    # ------------------------------------------------------------------

    def check_spf(self, domain: str) -> dict[str, Any]:
        """Look up SPF (TXT) records for *domain*.

        Returns
        -------
        A dict with:
        * ``exists`` -- whether an SPF record was found.
        * ``record`` -- the raw SPF TXT string (or ``""``).
        * ``valid``  -- rudimentary validity check (starts with
          ``v=spf1``).
        """
        result: dict[str, Any] = {
            "domain": domain,
            "exists": False,
            "record": "",
            "valid": False,
        }
        try:
            answers = self._resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.lower().startswith("v=spf1"):
                    result["exists"] = True
                    result["record"] = txt
                    result["valid"] = self._validate_spf(txt)
                    break
            logger.debug("SPF for %s: %s", domain, result)
        except dns.resolver.NoAnswer:
            logger.debug("No TXT records found for %s", domain)
        except dns.resolver.NXDOMAIN:
            logger.warning("Domain %s does not exist (NXDOMAIN)", domain)
        except dns.exception.DNSException as exc:
            self.record_error(f"check_spf({domain})", exc)
        return result

    @staticmethod
    def _validate_spf(record: str) -> bool:
        """Basic SPF record validation."""
        if not record.lower().startswith("v=spf1"):
            return False
        # An SPF record should end with an "all" directive.
        parts = record.split()
        if not parts:
            return False
        last = parts[-1].lower()
        return last in ("-all", "~all", "+all", "?all")

    # ------------------------------------------------------------------
    # DKIM
    # ------------------------------------------------------------------

    # Selectors tried for DKIM lookup when no explicit selector is given.
    # Google's default is "google"; admins commonly add additional rotated
    # keys (e.g. "google2025"), and other ESPs may set selectors like
    # "selector1"/"selector2" (Microsoft 365), "default", "k1", "mail",
    # or "s1"/"s2".
    _DKIM_DEFAULT_SELECTORS: tuple[str, ...] = (
        "google",
        "google2025",
        "google2024",
        "google2023",
        "selector1",
        "selector2",
        "default",
        "k1",
        "mail",
        "s1",
        "s2",
    )

    def check_dkim(
        self,
        domain: str,
        selector: str | None = None,
        selectors: list[str] | None = None,
    ) -> dict[str, Any]:
        """Look up the DKIM record at ``<selector>._domainkey.<domain>``.

        If neither ``selector`` nor ``selectors`` is given, a small list of
        common selectors is tried; the first one that resolves to a record
        with ``p=`` wins.

        Parameters
        ----------
        domain:
            The domain to check.
        selector:
            A single DKIM selector to query. Mutually exclusive with
            ``selectors``.
        selectors:
            An ordered list of selectors to try. The first match wins.

        Returns
        -------
        A dict with:
        * ``exists`` -- whether a DKIM record was found.
        * ``record`` -- the raw DKIM TXT string (or ``""``).
        * ``selector`` -- the selector that matched (or the last one tried).
        * ``selectors_tried`` -- list of selectors actually queried.
        """
        if selector and selectors:
            raise ValueError("Pass either selector= or selectors=, not both")
        if selector:
            to_try = [selector]
        elif selectors:
            to_try = list(selectors)
        else:
            to_try = list(self._DKIM_DEFAULT_SELECTORS)

        result: dict[str, Any] = {
            "domain": domain,
            "selector": to_try[0] if to_try else "",
            "exists": False,
            "record": "",
            "selectors_tried": [],
        }
        for sel in to_try:
            qname = f"{sel}._domainkey.{domain}"
            result["selectors_tried"].append(sel)
            try:
                answers = self._resolver.resolve(qname, "TXT")
                for rdata in answers:
                    txt = rdata.to_text().strip('"')
                    if "p=" in txt:
                        result["exists"] = True
                        result["record"] = txt
                        result["selector"] = sel
                        logger.debug(
                            "DKIM for %s (selector=%s): match", domain, sel,
                        )
                        return result
            except dns.resolver.NoAnswer:
                logger.debug("No DKIM TXT record at %s", qname)
            except dns.resolver.NXDOMAIN:
                logger.debug("DKIM name %s does not exist", qname)
            except dns.exception.DNSException as exc:
                self.record_error(f"check_dkim({domain}, {sel})", exc)
        # No selector matched; return the last attempted as the surfaced one
        return result

    # ------------------------------------------------------------------
    # DMARC
    # ------------------------------------------------------------------

    def check_dmarc(self, domain: str) -> dict[str, Any]:
        """Look up the DMARC record at ``_dmarc.<domain>``.

        DMARC RFC 7489 §6.6.3 specifies that if no record exists at the
        full FQDN, receivers SHOULD fall back to the Organisational
        Domain (the registrable parent). We approximate that fallback by
        re-querying ``_dmarc.<parent>`` if the initial query yields no
        record. The ``inherited_from`` field reports the matching domain
        when fallback was used, and ``subdomain_policy`` carries the
        ``sp=`` value from the matching record.

        Returns
        -------
        A dict with:
        * ``exists`` -- whether a DMARC record was found.
        * ``record`` -- the raw DMARC TXT string (or ``""``).
        * ``policy`` -- the ``p=`` value.
        * ``subdomain_policy`` -- the ``sp=`` value (defaults to ``policy``
          per RFC 7489 when not set).
        * ``inherited_from`` -- the parent domain whose record was used,
          or ``""`` if the record was found at the queried domain itself.
        """
        result: dict[str, Any] = {
            "domain": domain,
            "exists": False,
            "record": "",
            "policy": "",
            "subdomain_policy": "",
            "inherited_from": "",
        }

        # Try the queried domain first, then progressively shorter parents.
        candidates = [domain]
        parts = domain.split(".")
        for i in range(1, max(len(parts) - 1, 1)):
            candidates.append(".".join(parts[i:]))

        for idx, cand in enumerate(candidates):
            qname = f"_dmarc.{cand}"
            try:
                answers = self._resolver.resolve(qname, "TXT")
                for rdata in answers:
                    txt = rdata.to_text().strip('"')
                    if txt.lower().startswith("v=dmarc1"):
                        result["exists"] = True
                        result["record"] = txt
                        result["policy"] = self._extract_dmarc_policy(txt)
                        result["subdomain_policy"] = (
                            self._extract_dmarc_subdomain_policy(txt)
                            or result["policy"]
                        )
                        if idx > 0:
                            result["inherited_from"] = cand
                        logger.debug("DMARC for %s: %s", domain, result)
                        return result
            except dns.resolver.NoAnswer:
                logger.debug("No DMARC TXT record at %s", qname)
            except dns.resolver.NXDOMAIN:
                logger.debug("DMARC name %s does not exist", qname)
            except dns.exception.DNSException as exc:
                self.record_error(f"check_dmarc({cand})", exc)
                # Stop walking the chain on transient errors to avoid
                # masking a real lookup failure as "no record".
                return result
        return result

    @staticmethod
    def _extract_dmarc_policy(record: str) -> str:
        """Extract the ``p=`` value from a DMARC record."""
        match = re.search(r"\bp=(\w+)", record, re.IGNORECASE)
        return match.group(1).lower() if match else ""

    @staticmethod
    def _extract_dmarc_subdomain_policy(record: str) -> str:
        """Extract the ``sp=`` value from a DMARC record (or '' if absent)."""
        match = re.search(r"\bsp=(\w+)", record, re.IGNORECASE)
        return match.group(1).lower() if match else ""

    # ------------------------------------------------------------------
    # MX
    # ------------------------------------------------------------------

    def check_mx(self, domain: str) -> dict[str, Any]:
        """Look up MX records for *domain* and check if they point to Google.

        Returns
        -------
        A dict with:
        * ``records`` -- a list of ``{"priority": int, "host": str}``
          dicts.
        * ``uses_google`` -- ``True`` if any MX host matches a known
          Google mail server.
        """
        result: dict[str, Any] = {
            "domain": domain,
            "records": [],
            "uses_google": False,
        }
        try:
            answers = self._resolver.resolve(domain, "MX")
            for rdata in answers:
                host = str(rdata.exchange).rstrip(".").lower()
                entry = {"priority": rdata.preference, "host": host}
                result["records"].append(entry)
                if host in _GOOGLE_MX_HOSTS or host.endswith(".google.com") or host.endswith(".googlemail.com"):
                    result["uses_google"] = True

            result["records"].sort(key=lambda r: r["priority"])
            logger.debug("MX for %s: %s", domain, result)
        except dns.resolver.NoAnswer:
            logger.debug("No MX records found for %s", domain)
        except dns.resolver.NXDOMAIN:
            logger.warning("Domain %s does not exist (NXDOMAIN)", domain)
        except dns.exception.DNSException as exc:
            self.record_error(f"check_mx({domain})", exc)
        return result

    # ------------------------------------------------------------------
    # Aggregate
    # ------------------------------------------------------------------

    def check_all(self, domain: str) -> dict[str, Any]:
        """Run all DNS checks for *domain* and return a combined result.

        Returns
        -------
        A dict with keys ``"spf"``, ``"dkim"``, ``"dmarc"``, and
        ``"mx"``, each containing the result of the corresponding
        check method.
        """
        logger.info("Running all DNS checks for %s", domain)
        return {
            "domain": domain,
            "spf": self.check_spf(domain),
            "dkim": self.check_dkim(domain),
            "dmarc": self.check_dmarc(domain),
            "mx": self.check_mx(domain),
        }


class _NullAuth:
    """Minimal stub so ``DNSClient`` can be instantiated without an auth manager."""

    credentials = None

    def build_service(self, *args, **kwargs):
        raise NotImplementedError("DNSClient does not use Google API services")
