# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Credential file discovery and profile management."""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_CREDENTIALS_DIR = "credentials"


def scan_credentials_dir(credentials_dir: str = DEFAULT_CREDENTIALS_DIR) -> list[dict]:
    """Scan a directory for service account JSON files.

    Returns a list of dicts with keys:
    - path: absolute path to the file
    - filename: basename
    - project_id: from the JSON
    - client_email: service account email
    - type: credential type (service_account, etc.)
    """
    results = []
    cred_path = Path(credentials_dir)
    if not cred_path.is_dir():
        return results

    for f in sorted(cred_path.glob("*.json")):
        try:
            with open(f) as fh:
                data = json.load(fh)
            if data.get("type") not in ("service_account", "authorized_user"):
                continue
            results.append({
                "path": str(f.resolve()),
                "filename": f.name,
                "project_id": data.get("project_id", ""),
                "client_email": data.get("client_email", ""),
                "type": data.get("type", "unknown"),
            })
        except (json.JSONDecodeError, OSError):
            logger.warning("Skipping invalid JSON file: %s", f)

    return results


def apply_profile(config: dict, profile_name: str) -> dict:
    """Apply a named profile from config['auth']['profiles'] to the config.

    Profile values override the top-level auth keys (credentials_file,
    subject, customer_id).  Returns the modified config.
    """
    profiles = config.get("auth", {}).get("profiles", {})
    if profile_name not in profiles:
        available = ", ".join(profiles.keys()) if profiles else "(none)"
        raise ValueError(
            f"Profile '{profile_name}' not found. Available profiles: {available}"
        )

    profile = profiles[profile_name]
    auth = config.setdefault("auth", {})
    for key in ("credentials_file", "subject", "customer_id", "method"):
        if key in profile:
            auth[key] = profile[key]

    logger.info("Applied profile '%s'", profile_name)
    return config


def list_profiles(config: dict) -> list[dict]:
    """Return a list of available profiles with their details."""
    profiles = config.get("auth", {}).get("profiles", {})
    result = []
    for name, settings in profiles.items():
        result.append({
            "name": name,
            "credentials_file": settings.get("credentials_file", ""),
            "subject": settings.get("subject", ""),
            "customer_id": settings.get("customer_id", "auto"),
        })
    return result
