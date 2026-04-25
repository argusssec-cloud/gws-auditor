# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Configuration loading for GWS Security Auditor."""

import os
from pathlib import Path

import yaml

from .constants import (
    DEFAULT_CACHE_DIR,
    DEFAULT_MAX_LOG_EVENTS,
    DEFAULT_MAX_RETRIES,
    DEFAULT_RATE_LIMIT_QPS,
    DEFAULT_REPORTS_DIR,
)

DEFAULT_CONFIG = {
    "auth": {
        "method": "service_account",
        "credentials_file": "credentials.json",
        "credentials_dir": "credentials",
        "subject": "",
        "customer_id": "auto",
        "subscription_type": "",
        "profile": "",
        "profiles": {},
    },
    "checks": {
        "levels": ["L1", "L2"],
        "sources": ["CIS", "OTHER", "GOOGLE", "CISA"],
        "sections": "all",
        "exclude": [],
        "exclude_sections": [],
    },
    "output": {
        "directory": DEFAULT_REPORTS_DIR,
        "formats": ["html", "json", "csv"],
    },
    "options": {
        "cache_data": True,
        "cache_directory": DEFAULT_CACHE_DIR,
        "org_units": "all",
        "max_retries": DEFAULT_MAX_RETRIES,
        "rate_limit_qps": DEFAULT_RATE_LIMIT_QPS,
        "max_log_events": DEFAULT_MAX_LOG_EVENTS,
        "chat_inactive_days": 90,
        "device_inactive_days": 90,
    },
    "ai": {
        "provider": "openai",
        "model": "",
        "api_key": "",
        "temperature": 0.1,
        "max_tokens": 4096,
        "business_context": "",
        "aws_region": "us-east-1",
        "aws_profile": "",
        "base_url": "",
    },
    "network": {
        "proxy": None,
        "no_proxy": None,
        "ca_cert": None,
        "disable_ssl_verification": False,
    },
    "agent": {
        "console_url": "https://console.argussec.io",
        "api_key": "",
    },
}


def load_config(config_path: str | None = None) -> dict:
    """Load configuration from YAML file, falling back to defaults."""
    config = _deep_copy_dict(DEFAULT_CONFIG)

    if config_path and os.path.exists(config_path):
        with open(config_path, "r") as f:
            user_config = yaml.safe_load(f) or {}
        _deep_merge(config, user_config)

    return config


def _deep_copy_dict(d: dict) -> dict:
    """Deep copy a dict of primitives and lists."""
    result = {}
    for k, v in d.items():
        if isinstance(v, dict):
            result[k] = _deep_copy_dict(v)
        elif isinstance(v, list):
            result[k] = list(v)
        else:
            result[k] = v
    return result


# Keys whose values must never appear in reports or outputs.
_SENSITIVE_KEYS = frozenset({
    "api_key", "api_keys", "apikey", "secret", "password", "token",
    "credentials_file", "credential", "credentials",
    "subject",          # delegated admin email
    "proxy", "no_proxy",
    "ca_cert",
    "aws_profile",
    "base_url",         # may contain embedded tokens
    "client_id", "client_secret",
    "refresh_token", "access_token",
    "authorization", "bearer",
})

_REDACTED = "***REDACTED***"


def sanitize_config_for_report(config: dict) -> dict:
    """Return a deep copy of *config* with sensitive values redacted.

    Any key whose lowercase name appears in ``_SENSITIVE_KEYS`` will have
    its value replaced with ``"***REDACTED***"``.  Nested dicts and lists
    of dicts are handled recursively.
    """
    return _sanitize(config)


def _sanitize(obj):
    """Recursively redact sensitive keys from dicts/lists."""
    if isinstance(obj, dict):
        return {
            k: (_REDACTED if k.lower() in _SENSITIVE_KEYS else _sanitize(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_sanitize(item) for item in obj]
    return obj


def _deep_merge(base: dict, override: dict) -> None:
    """Deep merge override into base dict in-place."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
