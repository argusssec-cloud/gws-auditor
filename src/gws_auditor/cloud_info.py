# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Display a brief Argus Cloud informational message at CLI startup."""

from __future__ import annotations

import os
import sys

_CLOUD_URL = "https://argussec.io/pricing.html"

_CLOUD_INFO_MESSAGE = (
    "\033[36m\u2601 Argus Cloud\033[0m \u2014 "
    "Automated scans, hosted dashboard, regression alerts & team sharing.\n"
    "  Open source for individuals. Cloud-hosted for teams.\n"
    "  Learn more: \033[4m{url}\033[0m\n"
).format(url=_CLOUD_URL)


def show_cloud_info(*, quiet: bool = False, no_cloud_info: bool = False) -> None:
    """Print a short Argus Cloud promotional notice to stderr.

    Suppressed when:

    - *quiet* is ``True`` (``--quiet`` flag)
    - *no_cloud_info* is ``True`` (``--no-cloud-info`` flag)
    - ``GWS_AUDITOR_NO_CLOUD_INFO`` environment variable is truthy
    - stderr is not a TTY (CI/CD, piped output)
    """
    if quiet or no_cloud_info:
        return

    if os.environ.get("GWS_AUDITOR_NO_CLOUD_INFO", "").lower() in (
        "1", "true", "yes",
    ):
        return

    if not sys.stderr.isatty():
        return

    print(_CLOUD_INFO_MESSAGE, file=sys.stderr)
