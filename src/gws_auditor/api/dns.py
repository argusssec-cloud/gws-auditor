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

    def check_dkim(
        self, domain: str, selector: str = "google"
    ) -> dict[str, Any]:
        """Look up the DKIM record at ``<selector>._domainkey.<domain>``.

        Parameters
        ----------
        domain:
            The domain to check.
        selector:
            The DKIM selector (defaults to ``"google"``).

        Returns
        -------
        A dict with:
        * ``exists`` -- whether a DKIM record was found.
        * ``record`` -- the raw DKIM TXT string (or ``""``).
        * ``selector`` -- the selector that was used.
        """
        qname = f"{selector}._domainkey.{domain}"
        result: dict[str, Any] = {
            "domain": domain,
            "selector": selector,
            "exists": False,
            "record": "",
        }
        try:
            answers = self._resolver.resolve(qname, "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if "p=" in txt:
                    result["exists"] = True
                    result["record"] = txt
                    break
            logger.debug("DKIM for %s (selector=%s): %s", domain, selector, result)
        except dns.resolver.NoAnswer:
            logger.debug("No DKIM TXT record at %s", qname)
        except dns.resolver.NXDOMAIN:
            logger.debug("DKIM name %s does not exist", qname)
        except dns.exception.DNSException as exc:
            self.record_error(f"check_dkim({domain}, {selector})", exc)
        return result

    # ------------------------------------------------------------------
    # DMARC
    # ------------------------------------------------------------------

    def check_dmarc(self, domain: str) -> dict[str, Any]:
        """Look up the DMARC record at ``_dmarc.<domain>``.

        Returns
        -------
        A dict with:
        * ``exists`` -- whether a DMARC record was found.
        * ``record`` -- the raw DMARC TXT string (or ``""``).
        * ``policy`` -- the ``p=`` value (e.g. ``"reject"``,
          ``"quarantine"``, ``"none"``), or ``""`` if absent.
        """
        qname = f"_dmarc.{domain}"
        result: dict[str, Any] = {
            "domain": domain,
            "exists": False,
            "record": "",
            "policy": "",
        }
        try:
            answers = self._resolver.resolve(qname, "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.lower().startswith("v=dmarc1"):
                    result["exists"] = True
                    result["record"] = txt
                    result["policy"] = self._extract_dmarc_policy(txt)
                    break
            logger.debug("DMARC for %s: %s", domain, result)
        except dns.resolver.NoAnswer:
            logger.debug("No DMARC TXT record at %s", qname)
        except dns.resolver.NXDOMAIN:
            logger.debug("DMARC name %s does not exist", qname)
        except dns.exception.DNSException as exc:
            self.record_error(f"check_dmarc({domain})", exc)
        return result

    @staticmethod
    def _extract_dmarc_policy(record: str) -> str:
        """Extract the ``p=`` value from a DMARC record."""
        match = re.search(r"\bp=(\w+)", record, re.IGNORECASE)
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
