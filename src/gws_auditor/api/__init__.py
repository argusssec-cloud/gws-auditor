# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""API clients for Google Workspace services."""

from .base import BaseAPIClient
from .calendar import CalendarClient
from .cloud_identity import CloudIdentityClient
from .directory import DirectoryClient
from .dns import DNSClient
from .drive import DriveClient
from .gmail import GmailClient
from .groups import GroupsClient
from .policy import PolicyClient
from .reports import ReportsClient

__all__ = [
    "BaseAPIClient",
    "CalendarClient",
    "CloudIdentityClient",
    "DirectoryClient",
    "DNSClient",
    "DriveClient",
    "GmailClient",
    "GroupsClient",
    "PolicyClient",
    "ReportsClient",
]
