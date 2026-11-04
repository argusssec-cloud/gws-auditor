#!/usr/bin/env python3
"""Turn a cache/gws_data_*.json tenant snapshot into a golden fixture with no tenant identity.

    python scripts/anonymize_cache.py cache/gws_data_20260921_014950.json tests/fixtures/golden/enterprise_standard_2026-09.json.gz

Rewrites, deterministically (same input, same output): e-mail addresses, domains, org-unit ids
(also inside Policy API query strings), the customer id, IP addresses, device identifiers,
personal and group names, free-text descriptions and OAuth client ids. Token logs are reduced to
one entry per (client id, scope set) so the file stays small; every check that reads them keeps
its verdict (the caller verifies that with scripts/update_golden_expectations.py).
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import sys
from pathlib import Path

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
OU_ID_RE = re.compile(r"(orgUnits/|id:|orgUnitId\(')([0-9a-z]{6,})")
CUSTOMER_RE = re.compile(r"customers/C[0-9a-z]+|\bC[0-9a-z]{8,9}\b")
CLIENT_ID_RE = re.compile(r"\b(\d{6,})-([a-z0-9]+)\.apps\.googleusercontent\.com\b")
HASH_KEYS_EXACT_STRINGS = {"serialNumber", "deviceId", "resourceId", "etag"}
TEXT_KEYS = {"description", "fullName", "givenName", "familyName", "customReportingFormTitle",
             "customReportingFormDescription", "customHeaders", "destinationEmailAddress", "errorText"}
# "name" / "displayName" are personal only on these collections; elsewhere they are event,
# parameter, setting, policy or role names that checks match on.
NAMED_COLLECTIONS = {"groups", "chat_spaces", "shared_drives", "mobile_devices", "chromeos_devices", "endpoint_devices", "users"}
KEEP_NAME_PARENTS = {"policies", "roles"}


def _h(value: str, n: int = 8) -> str:
    return hashlib.sha1(value.encode()).hexdigest()[:n]


class Anonymizer:
    def __init__(self, data: dict):
        domains = [d.get("domainName") or d.get("domain_name") for d in data.get("domains", []) if isinstance(d, dict)]
        self.domain_map: dict[str, str] = {}
        for i, dom in enumerate(d for d in domains if d):
            self.domain_map[dom.lower()] = "example.com" if i == 0 else f"example-{_h(dom, 4)}.org"
        self.ou_map: dict[str, str] = {}
        for ou in data.get("org_units", []):
            raw = str(ou.get("orgUnitId", "")).split(":")[-1]
            if raw:
                self.ou_map[raw] = "ou" + _h(raw, 10)

    def domain(self, dom: str) -> str:
        dom_l = dom.lower()
        if dom_l in self.domain_map:
            return self.domain_map[dom_l]
        if dom_l.endswith((".google.com", ".googlemail.com", "google.com", "googleusercontent.com", "googleapis.com")):
            return dom
        return f"ext-{_h(dom_l, 6)}.example.net"

    def text(self, s: str, key: str, parents: tuple) -> str:
        def email(m):
            local = m.group(0).split("@")[0]
            return f"user-{_h(local, 6)}@{self.domain(m.group(1))}"
        s = EMAIL_RE.sub(email, s)
        s = OU_ID_RE.sub(lambda m: m.group(1) + self.ou_map.get(m.group(2), "ou" + _h(m.group(2), 10)), s)
        s = CUSTOMER_RE.sub(lambda m: "customers/C000000000" if m.group(0).startswith("customers/") else "C000000000", s)
        s = IPV4_RE.sub("10.0.0.1", s)
        for dom, repl in self.domain_map.items():
            s = re.sub(re.escape(dom), repl, s, flags=re.IGNORECASE)
        s = CLIENT_ID_RE.sub(lambda m: f"{int(_h(m.group(1), 12), 16)}-{_h(m.group(2), 10)}.apps.googleusercontent.com", s)
        if key in HASH_KEYS_EXACT_STRINGS and s:
            return key + "-" + _h(s)
        if parents and parents[0] in KEEP_NAME_PARENTS:
            return s
        if key in TEXT_KEYS and s:
            return f"{key}-{_h(s, 6)}"
        if key in ("name", "displayName") and s and parents and parents[-1] in NAMED_COLLECTIONS:
            return f"{key}-{_h(s, 6)}"
        return s

    def walk(self, obj, key: str = "", parents: tuple = ()):
        if isinstance(obj, dict):
            return {self.text(k, "", parents): self.walk(v, k, parents + (key,) if key else parents)
                    for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.walk(v, key, parents) for v in obj]
        if isinstance(obj, str):
            return self.text(obj, key, parents)
        return obj


def reduce_token_logs(logs: list) -> list:
    seen = set()
    out = []
    for log in logs:
        key = (_param(log, "client_id") or _param(log, "app_name"), json.dumps(_scopes(log), sort_keys=True),
               str(log.get("event_name") or _event_name(log)))
        if key in seen:
            continue
        seen.add(key)
        out.append(log)
    return out


def _param(log: dict, name: str):
    if isinstance(log.get(name), str):
        return log[name]
    params = log.get("parameters")
    if isinstance(params, dict) and params.get(name) is not None:
        return str(params[name])
    for ev in log.get("events", []) if isinstance(log.get("events"), list) else []:
        for p in ev.get("parameters", []) or []:
            if isinstance(p, dict) and p.get("name") == name:
                return str(p.get("value") or p.get("multiValue"))
    return ""


def _event_name(log: dict) -> str:
    events = log.get("events") if isinstance(log.get("events"), list) else []
    return "|".join(str(ev.get("name", "")) for ev in events if isinstance(ev, dict))


def _scopes(log: dict):
    for ev in log.get("events", []) if isinstance(log.get("events"), list) else []:
        for p in ev.get("parameters", []) or []:
            if isinstance(p, dict) and p.get("name") == "scope":
                return p.get("multiValue") or p.get("value")
    params = log.get("parameters")
    if isinstance(params, dict):
        return params.get("scope")
    return None


def anonymize(data: dict) -> dict:
    anon = Anonymizer(data)
    out = anon.walk(data)
    if isinstance(out.get("token_logs"), list):
        out["token_logs"] = reduce_token_logs(out["token_logs"])
    out["_golden"] = {"anonymized": True, "source_collected": data.get("collection_timestamp", "")}
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    src, dst = Path(argv[1]), Path(argv[2])
    data = json.loads(src.read_text())
    out = anonymize(data)
    payload = json.dumps(out, sort_keys=True, separators=(",", ":")).encode()
    if dst.suffix == ".gz":
        with open(dst, "wb") as raw_fh, gzip.GzipFile(filename="", mode="wb", fileobj=raw_fh, mtime=0) as fh:
            fh.write(payload)
    else:
        dst.write_bytes(payload)
    print(f"wrote {dst} ({dst.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
