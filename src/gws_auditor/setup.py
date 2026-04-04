# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Interactive setup wizard for GWS Security Auditor.

Automates GCP project configuration, API enablement, service account
creation, and config generation.  The only manual step is authorizing
domain-wide delegation scopes in the Google Admin Console.
"""

import base64
import json
import logging
import os
import platform
import secrets
import subprocess
import sys
import webbrowser
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from .constants import (
    REQUIRED_GCP_APIS,
    SCOPES,
    SERVICE_ACCOUNT_SCOPES,
    CUSTOMER_DISCOVERY_SCOPE,
)

logger = logging.getLogger(__name__)
console = Console()

_SA_ACCOUNT_ID = "gws-security-auditor"
_SA_DISPLAY_NAME = "GWS Security Auditor"

# Minimal scope needed for GCP project management during setup.
_SETUP_SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",
]


class SetupWizard:
    """Interactive wizard that automates GWS Auditor setup."""

    def __init__(self, project_id: str = "", subject: str = "",
                 credentials_dir: str = "credentials",
                 non_interactive: bool = False,
                 existing_sa_key: str = ""):
        self.project_id = project_id
        self.subject = subject
        self.credentials_dir = credentials_dir
        self.non_interactive = non_interactive
        self.existing_sa_key = existing_sa_key
        self._user_creds = None
        self._sa_email = ""
        self._sa_key_path = ""
        self._client_id = ""
        self._using_existing_sa = False

    def run(self) -> int:
        """Execute all setup steps. Returns 0 on success."""
        console.print()
        console.print(
            Panel("[bold cyan]GWS Security Auditor - Setup Wizard[/bold cyan]",
                  subtitle="Automates GCP project setup"),
        )
        console.print()

        try:
            self._step_authenticate()
            self._step_select_project()
            self._step_enable_apis()
            self._step_create_service_account()
            self._step_domain_wide_delegation()
            self._step_generate_config()
            self._step_validate()
        except KeyboardInterrupt:
            console.print("\n[yellow]Setup cancelled.[/yellow]")
            return 1
        except SetupError as exc:
            console.print(f"\n[bold red]Setup failed:[/bold red] {exc}")
            return 1

        console.print()
        console.print(
            Panel(
                "[bold green]Setup complete![/bold green]\n\n"
                "Run your first audit:\n"
                "  [cyan]gws-auditor[/cyan]\n\n"
                "Or validate connectivity:\n"
                "  [cyan]gws-auditor --validate[/cyan]",
                border_style="green",
            )
        )
        return 0

    # ------------------------------------------------------------------
    # Step 1: Authenticate to GCP
    # ------------------------------------------------------------------

    def _step_authenticate(self):
        console.print("[bold]Step 1/7: GCP Authentication[/bold]")

        # Strategy 1: Use an existing service account key (--existing-sa-key
        # or auto-detect from credentials/ dir or credentials.json)
        if self._try_existing_sa_key():
            return

        # Strategy 2: Use gcloud application-default credentials
        if self._try_gcloud_auth():
            return

        # Strategy 3: Use gcloud user credentials (not ADC)
        if self._try_gcloud_user_auth():
            return

        # Nothing worked — give guidance
        console.print()
        console.print(Panel(
            "[bold yellow]Could not find GCP credentials[/bold yellow]\n\n"
            "Try one of these options:\n\n"
            "[bold]Option A:[/bold] Use an existing service account key:\n"
            "  [cyan]gws-auditor setup --existing-sa-key credentials.json[/cyan]\n\n"
            "[bold]Option B:[/bold] Authenticate via gcloud:\n"
            "  [cyan]gcloud auth login[/cyan]\n"
            "  [cyan]gcloud config set project YOUR_PROJECT_ID[/cyan]\n"
            "  [cyan]gws-auditor setup[/cyan]\n\n"
            "[bold]Option C:[/bold] If 'Access blocked' by admin, ask your\n"
            "  Workspace admin to allowlist the Google Auth Library app,\n"
            "  or use Option A with an existing service account.",
            border_style="yellow",
            title="Authentication Help",
        ))
        raise SetupError("No GCP credentials available. See options above.")

    def _try_existing_sa_key(self) -> bool:
        """Try to use an existing service account JSON key for GCP management.

        This bypasses the OAuth flow entirely, which avoids the
        'Access blocked: admin needs to review Google Auth Library' error.
        The SA needs Editor/Owner role on the GCP project.
        """
        # Check explicit flag first
        key_paths = []
        if self.existing_sa_key:
            key_paths.append(self.existing_sa_key)

        # Auto-detect from common locations
        key_paths.append("credentials.json")
        creds_dir = Path(self.credentials_dir)
        if creds_dir.is_dir():
            key_paths.extend(sorted(creds_dir.glob("*.json")))

        for key_path in key_paths:
            path = Path(key_path) if isinstance(key_path, str) else key_path
            if not path.is_file():
                continue
            try:
                with open(path) as f:
                    key_data = json.load(f)
                if key_data.get("type") != "service_account":
                    continue

                from google.oauth2 import service_account as sa_module
                creds = sa_module.Credentials.from_service_account_file(
                    str(path),
                    scopes=_SETUP_SCOPES,
                )
                self._user_creds = creds
                self._using_existing_sa = True

                # Extract project from key
                project = key_data.get("project_id", "")
                if project and not self.project_id:
                    self.project_id = project

                # Pre-populate SA info so we can skip SA creation
                self._sa_email = key_data.get("client_email", "")
                self._client_id = key_data.get("client_id", "")
                self._sa_key_path = str(path)

                console.print(
                    f"  [green]Using existing service account: "
                    f"{self._sa_email}[/green]"
                )
                if project:
                    console.print(
                        f"  [green]Project: {project}[/green]"
                    )
                return True
            except Exception:
                continue
        return False

    def _try_gcloud_auth(self) -> bool:
        """Try to use gcloud application-default credentials."""
        try:
            from google.auth import default as google_auth_default
            creds, project = google_auth_default(scopes=_SETUP_SCOPES)
            if creds:
                self._user_creds = creds
                if project and not self.project_id:
                    self.project_id = project
                console.print(
                    f"  [green]Using GCP application-default credentials"
                    f"{f' (project: {project})' if project else ''}[/green]"
                )
                return True
        except Exception as exc:
            logger.debug("gcloud ADC auth failed: %s", exc)
        return False

    def _try_gcloud_user_auth(self) -> bool:
        """Try to get credentials from gcloud CLI directly."""
        try:
            result = subprocess.run(
                ["gcloud", "auth", "print-access-token"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                from google.oauth2.credentials import Credentials
                token = result.stdout.strip()
                self._user_creds = Credentials(token=token)

                # Try to get project
                proj_result = subprocess.run(
                    ["gcloud", "config", "get-value", "project"],
                    capture_output=True, text=True, timeout=10,
                )
                if proj_result.returncode == 0 and proj_result.stdout.strip():
                    project = proj_result.stdout.strip()
                    if not self.project_id:
                        self.project_id = project

                console.print(
                    f"  [green]Using gcloud CLI credentials"
                    f"{f' (project: {self.project_id})' if self.project_id else ''}[/green]"
                )
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return False

    # ------------------------------------------------------------------
    # Step 2: Select or create GCP project
    # ------------------------------------------------------------------

    def _step_select_project(self):
        console.print("\n[bold]Step 2/7: GCP Project[/bold]")

        if self.project_id:
            console.print(f"  Using project: [cyan]{self.project_id}[/cyan]")
            return

        # List existing projects
        projects = self._list_projects()

        if projects and not self.non_interactive:
            table = Table(title="Available GCP Projects", show_lines=False)
            table.add_column("#", style="dim", width=4)
            table.add_column("Project ID", style="cyan")
            table.add_column("Name")
            for i, p in enumerate(projects[:10], 1):
                table.add_row(str(i), p["projectId"], p.get("name", ""))
            table.add_row("N", "Create new project", "[dim]auto-generated ID[/dim]")
            console.print(table)

            choice = Prompt.ask(
                "  Select project",
                default="1",
            )
            if choice.upper() == "N":
                self._create_project()
            else:
                try:
                    idx = int(choice) - 1
                    self.project_id = projects[idx]["projectId"]
                except (ValueError, IndexError):
                    self.project_id = projects[0]["projectId"]
        elif not projects:
            self._create_project()
        else:
            # Non-interactive: use first project
            self.project_id = projects[0]["projectId"]

        console.print(f"  [green]Using project: {self.project_id}[/green]")

    def _list_projects(self) -> list[dict]:
        """List GCP projects the user has access to."""
        try:
            from googleapiclient.discovery import build
            import google.auth
            import google_auth_httplib2
            import httplib2

            http = httplib2.Http()
            authed_http = google_auth_httplib2.AuthorizedHttp(
                self._user_creds, http=http,
            )
            service = build(
                "cloudresourcemanager", "v1",
                http=authed_http, cache_discovery=False,
            )
            result = service.projects().list(
                filter="lifecycleState:ACTIVE",
                pageSize=20,
            ).execute()
            return result.get("projects", [])
        except Exception as exc:
            logger.debug("Could not list projects: %s", exc)
            return []

    def _create_project(self):
        """Create a new GCP project."""
        suffix = secrets.token_hex(4)
        self.project_id = f"gws-audit-{suffix}"
        console.print(f"  Creating project [cyan]{self.project_id}[/cyan]...")

        try:
            from googleapiclient.discovery import build
            import google_auth_httplib2
            import httplib2

            http = httplib2.Http()
            authed_http = google_auth_httplib2.AuthorizedHttp(
                self._user_creds, http=http,
            )
            service = build(
                "cloudresourcemanager", "v1",
                http=authed_http, cache_discovery=False,
            )
            service.projects().create(
                body={
                    "projectId": self.project_id,
                    "name": "GWS Security Audit",
                }
            ).execute()
            console.print(f"  [green]Project created: {self.project_id}[/green]")
        except Exception as exc:
            raise SetupError(f"Failed to create project: {exc}")

    # ------------------------------------------------------------------
    # Step 3: Enable required APIs
    # ------------------------------------------------------------------

    def _step_enable_apis(self):
        console.print("\n[bold]Step 3/7: Enable APIs[/bold]")
        console.print(f"  Checking {len(REQUIRED_GCP_APIS)} required APIs...")

        try:
            from googleapiclient.discovery import build
            import google_auth_httplib2
            import httplib2

            http = httplib2.Http()
            authed_http = google_auth_httplib2.AuthorizedHttp(
                self._user_creds, http=http,
            )
            service = build(
                "serviceusage", "v1",
                http=authed_http, cache_discovery=False,
            )

            # First try batch enable
            parent = f"projects/{self.project_id}"
            try:
                service.services().batchEnable(
                    parent=parent,
                    body={"serviceIds": REQUIRED_GCP_APIS},
                ).execute()
                console.print("  [green]All APIs enabled[/green]")
                console.print(
                    "\n  [bold yellow]Important:[/bold yellow] The Google Chat API "
                    "requires an additional configuration step.\n"
                    "  You must configure a Chat app in the GCP Console for the "
                    "admin-scoped Chat endpoints to work.\n"
                    "  Go to: [cyan]https://console.cloud.google.com/apis/api/"
                    "chat.googleapis.com/hangouts-chat?project="
                    f"{self.project_id}[/cyan]\n"
                    "  Fill in the required fields (App name, etc.) and click Save.\n"
                    "  The app does not need to be published or visible to users."
                )
                if not self.non_interactive:
                    Prompt.ask("\n  Press Enter to continue")
                return
            except Exception as enable_err:
                logger.debug("Batch enable failed: %s", enable_err)

            # If enable failed (permission denied), check which are already on
            console.print(
                "  [yellow]Cannot enable APIs — the authenticated account lacks "
                "the required GCP project permissions.[/yellow]\n"
                "  Needed: [bold]Editor[/bold], [bold]Owner[/bold], or "
                "[bold]Service Usage Admin[/bold] "
                "(roles/serviceusage.serviceUsageAdmin) role\n"
                "  on project [cyan]{project}[/cyan].\n"
                "  Grant it at: [cyan]https://console.cloud.google.com/"
                "iam-admin/iam?project={project}[/cyan]\n".format(
                    project=self.project_id)
            )
            console.print("  Checking existing API status...")
            enabled = set()
            try:
                resp = service.services().list(
                    parent=parent,
                    filter="state:ENABLED",
                    pageSize=200,
                ).execute()
                for svc in resp.get("services", []):
                    name = svc.get("config", {}).get("name", "")
                    enabled.add(name)
            except Exception:
                pass

            missing = [api for api in REQUIRED_GCP_APIS if api not in enabled]
            if not missing:
                console.print("  [green]All required APIs are already enabled[/green]")
            else:
                console.print(
                    f"  [yellow]{len(missing)} API(s) may need manual enablement:[/yellow]"
                )
                for api in missing:
                    console.print(f"    - {api}")
                console.print(
                    f"\n  Enable them at:\n"
                    f"  [cyan]https://console.cloud.google.com/apis/library"
                    f"?project={self.project_id}[/cyan]"
                )
                if not self.non_interactive:
                    Prompt.ask("\n  Press Enter to continue")

        except Exception as exc:
            console.print(
                f"  [yellow]Could not check API status: {exc}[/yellow]\n"
                f"  Enable APIs manually at:\n"
                f"  [cyan]https://console.cloud.google.com/apis/library"
                f"?project={self.project_id}[/cyan]"
            )
            if not self.non_interactive:
                Prompt.ask("\n  Press Enter to continue")

    # ------------------------------------------------------------------
    # Step 4: Create service account + key
    # ------------------------------------------------------------------

    def _step_create_service_account(self):
        console.print("\n[bold]Step 4/7: Service Account[/bold]")

        # If we already loaded an existing SA key, skip creation
        if self._using_existing_sa and self._sa_email:
            console.print(
                f"  [green]Using existing service account: "
                f"{self._sa_email}[/green]"
            )
            console.print(
                f"  [green]Key file: {self._sa_key_path}[/green]"
            )

            # Copy to credentials dir if not already there
            creds_dir = Path(self.credentials_dir)
            creds_dir.mkdir(parents=True, exist_ok=True)
            key_in_dir = creds_dir / Path(self._sa_key_path).name
            if not key_in_dir.exists() and Path(self._sa_key_path).exists():
                import shutil
                shutil.copy2(self._sa_key_path, key_in_dir)
                self._sa_key_path = str(key_in_dir)
                console.print(
                    f"  [dim]Copied to {key_in_dir}[/dim]"
                )
            return

        try:
            from googleapiclient.discovery import build
            import google_auth_httplib2
            import httplib2

            http = httplib2.Http()
            authed_http = google_auth_httplib2.AuthorizedHttp(
                self._user_creds, http=http,
            )
            iam = build("iam", "v1", http=authed_http, cache_discovery=False)

            # Create service account (or find existing)
            sa_name = f"projects/{self.project_id}/serviceAccounts/{_SA_ACCOUNT_ID}@{self.project_id}.iam.gserviceaccount.com"

            try:
                sa = iam.projects().serviceAccounts().get(
                    name=sa_name,
                ).execute()
                console.print(
                    f"  Service account already exists: "
                    f"[cyan]{sa['email']}[/cyan]"
                )
            except Exception:
                console.print(f"  Creating service account [cyan]{_SA_ACCOUNT_ID}[/cyan]...")
                sa = iam.projects().serviceAccounts().create(
                    name=f"projects/{self.project_id}",
                    body={
                        "accountId": _SA_ACCOUNT_ID,
                        "serviceAccount": {
                            "displayName": _SA_DISPLAY_NAME,
                        },
                    },
                ).execute()
                console.print(f"  [green]Created: {sa['email']}[/green]")

            self._sa_email = sa["email"]

            # Create key
            console.print("  Generating JSON key...")
            key_result = iam.projects().serviceAccounts().keys().create(
                name=f"projects/{self.project_id}/serviceAccounts/{self._sa_email}",
                body={"keyAlgorithm": "KEY_ALG_RSA_2048"},
            ).execute()

            # Decode and save key
            key_data = base64.b64decode(key_result["privateKeyData"])
            key_json = json.loads(key_data)

            # Extract client_id for DWD step
            self._client_id = key_json.get("client_id", "")

            # Save to credentials directory
            Path(self.credentials_dir).mkdir(parents=True, exist_ok=True)
            key_filename = f"{self.project_id}.json"
            self._sa_key_path = str(
                Path(self.credentials_dir) / key_filename
            )
            with open(self._sa_key_path, "w") as f:
                json.dump(key_json, f, indent=2)

            console.print(
                f"  [green]Key saved to: {self._sa_key_path}[/green]"
            )

        except SetupError:
            raise
        except Exception as exc:
            raise SetupError(f"Failed to create service account: {exc}")

    # ------------------------------------------------------------------
    # Step 5: Domain-Wide Delegation (manual, guided with pre-filled URL)
    # ------------------------------------------------------------------

    def _step_domain_wide_delegation(self):
        console.print("\n[bold]Step 5/7: Domain-Wide Delegation[/bold]")

        all_scopes = SCOPES + SERVICE_ACCOUNT_SCOPES
        scope_string = ",".join(all_scopes)

        # Pre-filled DWD URL (same technique as GAM) — admin just clicks Authorize
        dwd_url = (
            "https://admin.google.com/ac/owl/domainwidedelegation"
            f"?clientScopeToAdd={scope_string}"
            f"&clientIdToAdd={self._client_id}"
            "&overwriteClientId=true"
        )

        panel_text = (
            "[bold yellow]MANUAL STEP REQUIRED[/bold yellow]\n\n"
            "Open this link — it pre-fills the Client ID and all scopes:\n\n"
            f"  [bold cyan][link={dwd_url}]Click here to authorize[/link][/bold cyan]\n\n"
            "Then click [bold]\"AUTHORIZE\"[/bold] in the Admin Console.\n\n"
            f"[dim]Client ID: {self._client_id}[/dim]\n"
            f"[dim]Scopes: {len(all_scopes)} read-only scopes[/dim]"
        )

        console.print(Panel(panel_text, border_style="yellow",
                            title="Domain-Wide Delegation"))

        # Open the pre-filled URL in browser
        if not self.non_interactive:
            try:
                webbrowser.open(dwd_url)
                console.print("  [dim]Browser opened with pre-filled DWD form[/dim]")
            except Exception:
                pass

        # Save the URL and raw scopes for reference
        scope_file = Path(self.credentials_dir) / "dwd_scopes.txt"
        with open(scope_file, "w") as f:
            f.write(f"Pre-filled authorization URL:\n{dwd_url}\n\n")
            f.write(f"Client ID:\n{self._client_id}\n\n")
            f.write(f"OAuth Scopes ({len(all_scopes)} scopes, paste as one line):\n{scope_string}\n")
        console.print(
            f"  [dim]Authorization URL also saved to: {scope_file}[/dim]"
        )

        if not self.non_interactive:
            Prompt.ask(
                "\n  Press [bold]Enter[/bold] when you've clicked Authorize"
            )
        console.print("  [green]Domain-Wide Delegation step acknowledged[/green]")

        # App trust guidance
        if not self.non_interactive:
            console.print()
            console.print(Panel(
                "[dim]If your organization restricts third-party apps, "
                "you may also need to mark this app as trusted:\n\n"
                "  [link=https://admin.google.com/ac/owl/list?tab=configuredApps]"
                "Admin Console > Security > API Controls > App Access Control"
                "[/link]\n\n"
                "Add the Client ID above as a trusted app.[/dim]",
                border_style="dim",
                title="[dim]Optional: App Trust[/dim]",
            ))

    # ------------------------------------------------------------------
    # Step 6: Generate config.yaml
    # ------------------------------------------------------------------

    def _step_generate_config(self):
        console.print("\n[bold]Step 6/7: Configuration[/bold]")

        if not self.subject and not self.non_interactive:
            self.subject = Prompt.ask(
                "  Super admin email for impersonation",
            )

        config_path = Path("config.yaml")
        if config_path.exists() and not self.non_interactive:
            if not Confirm.ask(
                f"  [yellow]{config_path} already exists. Overwrite?[/yellow]",
                default=False,
            ):
                console.print("  [dim]Keeping existing config.yaml[/dim]")
                return

        config_content = f"""# GWS Security Auditor Configuration
# Generated by: gws-auditor setup

auth:
  method: service_account
  credentials_file: {self._sa_key_path}
  credentials_dir: {self.credentials_dir}
  subject: {self.subject}
  customer_id: auto

checks:
  levels: [L1, L2]
  sources: [CIS, OTHER, GOOGLE, CISA]
  sections: all
  exclude: []

output:
  directory: ./reports
  formats: [html, json, csv]

options:
  cache_data: true
  cache_directory: ./cache
  org_units: all
  max_retries: 5
  rate_limit_qps: 10
"""

        with open(config_path, "w") as f:
            f.write(config_content)

        console.print(f"  [green]Generated {config_path}[/green]")

    # ------------------------------------------------------------------
    # Step 7: Validate connectivity
    # ------------------------------------------------------------------

    def _step_validate(self):
        console.print("\n[bold]Step 7/7: Validation[/bold]")

        if not self._sa_key_path or not self.subject:
            console.print(
                "  [yellow]Skipping validation "
                "(missing credentials or subject)[/yellow]"
            )
            return

        try:
            from .auth import AuthManager
            from .config import load_config

            config = load_config("config.yaml")
            auth_mgr = AuthManager(config)

            # --- Per-scope DWD verification ---
            console.print("  Verifying domain-wide delegation scopes...")
            all_scopes = SCOPES + SERVICE_ACCOUNT_SCOPES
            scope_results = self._verify_dwd_scopes(
                self._sa_key_path, self.subject, all_scopes,
            )

            scope_table = Table(show_header=True, title="DWD Scope Verification")
            scope_table.add_column("Scope", style="dim", max_width=50)
            scope_table.add_column("Status", width=6)

            scope_ok = 0
            scope_fail = 0
            failed_scopes = []
            for scope, ok in scope_results:
                short = scope.rsplit("/", 1)[-1]
                if ok:
                    scope_table.add_row(short, "[green]OK[/green]")
                    scope_ok += 1
                else:
                    scope_table.add_row(short, "[red]FAIL[/red]")
                    scope_fail += 1
                    failed_scopes.append(scope)

            console.print(scope_table)

            if scope_fail:
                # Re-generate pre-filled URL with only failing scopes
                fix_url = (
                    "https://admin.google.com/ac/owl/domainwidedelegation"
                    f"?clientScopeToAdd={','.join(failed_scopes)}"
                    f"&clientIdToAdd={self._client_id}"
                    "&overwriteClientId=true"
                )
                console.print(
                    f"\n  [yellow]{scope_fail} scope(s) not authorized. "
                    f"Open this link to add the missing scopes:[/yellow]"
                )
                console.print(f"  [cyan]{fix_url}[/cyan]")
            else:
                console.print(
                    f"\n  [green]All {scope_ok} DWD scopes verified![/green]"
                )

            # --- API endpoint validation ---
            console.print("\n  Validating API endpoints...")
            results = auth_mgr.validate_access()

            table = Table(show_header=True)
            table.add_column("API", style="bold")
            table.add_column("Status")
            table.add_column("Details")

            ok_count = 0
            fail_count = 0
            for r in results:
                if r["status"] == "ok":
                    status = "[green]OK[/green]"
                    ok_count += 1
                else:
                    status = "[red]FAIL[/red]"
                    fail_count += 1
                table.add_row(r["api"], status, r["message"][:60])

            console.print(table)

            if fail_count:
                console.print(
                    f"\n  [yellow]{fail_count} API(s) failed. "
                    f"Check API enablement in GCP Console.[/yellow]"
                )
            else:
                console.print(
                    f"\n  [green]All {ok_count} APIs accessible![/green]"
                )

        except Exception as exc:
            console.print(f"  [yellow]Validation failed: {exc}[/yellow]")
            console.print(
                "  [dim]You can validate later with: "
                "gws-auditor --validate[/dim]"
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _verify_dwd_scopes(
        sa_key_path: str, subject: str, scopes: list[str],
    ) -> list[tuple[str, bool]]:
        """Test each DWD scope individually by requesting a delegated token.

        Returns a list of (scope, success_bool) tuples.  This pinpoints
        exactly which scopes are missing from the DWD authorization.
        """
        from google.oauth2 import service_account as sa_module

        results = []
        for scope in scopes:
            try:
                creds = sa_module.Credentials.from_service_account_file(
                    sa_key_path, scopes=[scope], subject=subject,
                )
                # Force a token refresh to test delegation
                import google.auth.transport.requests
                creds.refresh(google.auth.transport.requests.Request())
                results.append((scope, True))
            except Exception:
                results.append((scope, False))
        return results

    @staticmethod
    def _copy_to_clipboard(text: str):
        """Best-effort copy text to system clipboard."""
        try:
            system = platform.system()
            if system == "Darwin":
                subprocess.run(
                    ["pbcopy"], input=text.encode(), check=True,
                    capture_output=True,
                )
            elif system == "Linux":
                for cmd in (["xclip", "-selection", "clipboard"],
                            ["xsel", "--clipboard", "--input"]):
                    try:
                        subprocess.run(
                            cmd, input=text.encode(), check=True,
                            capture_output=True,
                        )
                        break
                    except FileNotFoundError:
                        continue
            elif system == "Windows":
                subprocess.run(
                    ["clip"], input=text.encode(), check=True,
                    capture_output=True,
                )
        except Exception:
            pass  # Clipboard is nice-to-have, not critical


class SetupError(Exception):
    """Raised when a setup step fails."""
