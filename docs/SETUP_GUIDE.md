# GWS Security Auditor: Deployment & Setup Guide

This guide provides a step-by-step walkthrough to configure and execute a professional security audit on your Google Workspace environment.

---

## Phase 1: Google Cloud Infrastructure
The auditor requires a "bridge" to communicate with your Google Workspace. We configure this using the Google Cloud Console.

1.  **Project Selection:**
    * Log in to the [Google Cloud Console](https://console.cloud.google.com/).
    * At the top of the screen, click the project dropdown menu.
    * **If you have an existing project:** Select it from the list.
    * **If you need a new project:** Click **"New Project"**, name it (e.g., `GWS-Security-Audit`), and click **Create**.

2.  **Activate API Services:**
    * Navigate to **APIs & Services** > **Library** in the left-hand sidebar.
    * Search for and click **Enable** for each of the following APIs:
        * **Admin SDK API**
        * **Gmail API**
        * **Google Drive API**
        * **Google Calendar API**
        * **Groups Settings API**
        * **Cloud Identity**
        * **Chrome Policy API**
        * **Google Chat API**
        * **Google Workspace Alert Center API**
        * **Enterprise License Manager API**

> **Note:** If you enable these for the first time, wait 2–3 minutes for the changes to propagate across Google's systems before proceeding.

3.  **Configure the Google Chat API as a Chat App:**

    The Chat API requires a **Chat app configuration** in addition to being enabled — without this, admin-scoped endpoints (e.g., `spaces.search`) return HTTP 404.

    1. Go to **APIs & Services** > **Google Chat API** > **[Configuration](https://console.cloud.google.com/apis/api/chat.googleapis.com/hangouts-chat)** tab.
    2. Fill in the required fields:
        * **App name:** `GWS Security Auditor` (or any name)
        * **Avatar URL:** leave blank or use any image URL
        * **Description:** `Service account for security auditing`
    3. Under **Functionality**, uncheck both checkboxes (the auditor does not need to receive messages).
    4. Under **Visibility**, select **Make this Google Chat app available to specific people and groups in your domain** and leave the list empty — or select a test user.
    5. Click **Save**.

    > The app does not need to be published or visible to users. This configuration step simply satisfies the API prerequisite so that admin read-only endpoints work.

---

## Phase 2: Create a Service Account with Domain-Wide Delegation

A service account allows the auditor to access all Google Workspace data without interactive login prompts. This is the **recommended method** — it provides access to all APIs including Chat Admin, Alert Center, and App-Specific Password auditing.

### Step 2.1: Create the Service Account

1.  In the [Google Cloud Console](https://console.cloud.google.com/), navigate to **IAM & Admin** > **Service Accounts**.
2.  Click **+ CREATE SERVICE ACCOUNT** at the top.
3.  Fill in:
    * **Service account name:** `gws-security-auditor`
    * **Service account ID:** auto-populated (e.g., `gws-security-auditor@your-project.iam.gserviceaccount.com`)
    * **Description:** `Service account for GWS Security Auditor`
4.  Click **CREATE AND CONTINUE**.
5.  Skip the "Grant this service account access to project" step — click **CONTINUE**.
6.  Skip the "Grant users access to this service account" step — click **DONE**.

### Step 2.2: Download the JSON Key

1.  In the Service Accounts list, click on the service account you just created.
2.  Go to the **Keys** tab.
3.  Click **ADD KEY** > **Create new key**.
4.  Select **JSON** and click **CREATE**.
5.  A `.json` file will be downloaded automatically.
6.  **Rename** this file to `credentials.json` and move it into the `credentials/` folder inside your auditor project directory.

### Step 2.3: Enable Domain-Wide Delegation

1.  Still on the service account details page, go to the **Details** tab.
2.  Expand the **Advanced settings** section.
3.  Under **Domain-wide delegation**, click **ENABLE DOMAIN-WIDE DELEGATION** (if not already enabled).
4.  Copy the **Client ID** (a numeric string, e.g., `106731238360512345`) — you will need this in the next step.

### Step 2.4: Authorize Scopes in Google Admin Console

1.  Log in to the [Google Admin Console](https://admin.google.com/) with a **Super Admin** account.
2.  Navigate to **Security** > **Access and data control** > **API controls**.
3.  In the **Domain-wide delegation** section, click **MANAGE DOMAIN WIDE DELEGATION**.
4.  Click **Add new**.
5.  In the **Client ID** field, paste the Client ID you copied in Step 2.3.
6.  In the **OAuth scopes** field, paste the following comma-separated list of all required scopes:

```
https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.domain.readonly,https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly,https://www.googleapis.com/auth/admin.directory.orgunit.readonly,https://www.googleapis.com/auth/admin.directory.device.mobile.readonly,https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly,https://www.googleapis.com/auth/admin.reports.audit.readonly,https://www.googleapis.com/auth/admin.reports.usage.readonly,https://www.googleapis.com/auth/apps.groups.settings,https://www.googleapis.com/auth/gmail.settings.basic,https://www.googleapis.com/auth/calendar,https://www.googleapis.com/auth/drive.readonly,https://www.googleapis.com/auth/cloud-identity.policies.readonly,https://www.googleapis.com/auth/cloud-identity.devices.readonly,https://www.googleapis.com/auth/chrome.management.policy.readonly,https://www.googleapis.com/auth/apps.licensing,https://www.googleapis.com/auth/chat.admin.spaces.readonly,https://www.googleapis.com/auth/chat.admin.memberships.readonly,https://www.googleapis.com/auth/admin.directory.user.security,https://www.googleapis.com/auth/apps.alerts,https://www.googleapis.com/auth/admin.directory.customer.readonly
```

7.  Click **AUTHORIZE**.

> **Important:** Double-check that all 22 scopes appear in the authorized list. Missing scopes will cause specific checks to fail silently or return incomplete data.

---

## Phase 3: Configuration & Installation

1.  **Configure Settings:**
    * Locate the file named `config.yaml.sample` in your project folder.
    * **Rename this file** to `config.yaml` (remove the `.sample` extension).
    * Open `config.yaml` in a text editor and update these fields:
        * `auth.method`: Set to `service_account`
        * `auth.credentials_file`: Set to `./credentials/credentials.json`
        * `auth.subject`: Enter your **Google Workspace Super Admin email address**
        * `auth.customer_id`: Enter your **Google Workspace Customer ID** (find it in Admin Console > Account > Account Settings, or use `my_customer`)
    * Your `auth` section should look like:
      ```yaml
      auth:
        method: service_account
        credentials_file: ./credentials/credentials.json
        subject: admin@yourdomain.com
        customer_id: C0xxxxxxx
      ```
    * Save and close the file.

2.  **Prepare the Environment:**
    * Open your Terminal (CMD or PowerShell on Windows).
    * Navigate to the folder where you saved the auditor files.
    * Create a local workspace:
      ```bash
      python -m venv .venv
      ```
    * **Activate it:**
        * *Windows:* `.venv\Scripts\activate`
        * *Mac/Linux:* `source .venv/bin/activate`

3.  **Install Dependencies:**
    * Run: `pip install -e ".[dashboard]"`

---

## Phase 4: Running the Audit

1.  **Verification (Dry Run):**
    Ensure the connection is successful:
    ```bash
    gws-auditor --dry-run --config config.yaml
    ```
    Unlike OAuth, no browser window will open — the service account authenticates automatically.

2.  **Execute the Scan:**
    Once verified, run the full audit:
    ```bash
    gws-auditor --config config.yaml
    ```

---

## Phase 5: Interpreting Results
After the audit, navigate to the `/reports` folder in your project directory:
* **HTML Report:** Open this file in your browser for a clear, interactive summary of your security posture.
* **Dashboard:** For a visual, category-based analysis, run:
  ```bash
  gws-auditor dashboard
  ```
  Then open http://127.0.0.1:8050 in your browser.

---

# Appendix A: OAuth Method (Alternative)

If you cannot create a service account (e.g., restricted GCP access), you can use the OAuth method instead. Note that **3 features will be unavailable** with OAuth: Chat space auditing, App-Specific Password auditing, and Alert Center rule detection.

1.  **OAuth Consent Screen:**
    * Go to **APIs & Services** > **OAuth consent screen**.
    * Select **Internal** (for your company) or **External** (if testing for multiple clients). Click **Create**.
    * Fill in the mandatory App Information fields and your contact email. Click **Save and Continue** through the remaining screens.

2.  **Create Credentials:**
    * Go to **APIs & Services** > **Credentials**.
    * Click **+ CREATE CREDENTIALS** and select **OAuth client ID**.
    * For *Application type*, select **Desktop app**. Click **Create**.
    * Click **DOWNLOAD JSON**.
    * Rename this file to `credentials.json` and move it into the `credentials/` folder.

3.  **Update config.yaml:**
    ```yaml
    auth:
      method: oauth
      credentials_file: ./credentials/credentials.json
      subject: admin@yourdomain.com
      customer_id: my_customer
    ```

4.  When you run the auditor, a browser window will open. Log in with your Admin account and click **"Allow"**.

---

# Appendix B: Troubleshooting Common Issues

1.  **Error: 403 Forbidden / SERVICE_DISABLED**
    * **Cause:** One of the required APIs is not enabled in your Google Cloud project.
    * **Solution:** Navigate to **APIs & Services > Library**, find the missing API, and click **Enable**. Wait 3 minutes for propagation.

2.  **Error: 403 Forbidden / PERMISSION_DENIED**
    * **Cause:** The service account is missing a required OAuth scope in domain-wide delegation.
    * **Solution:** Go to **Admin Console > Security > API controls > Domain-wide Delegation**, edit the service account entry, and verify all 22 scopes are listed.

3.  **Error: 401 Unauthorized / invalid_grant**
    * **Cause:** The `subject` email in `config.yaml` is not a Super Admin, or domain-wide delegation is not enabled.
    * **Solution:** Verify the `subject` is a Super Admin account. Ensure domain-wide delegation is enabled on the service account (GCP Console > IAM & Admin > Service Accounts > Details > Advanced settings).

4.  **Error: FileNotFoundError**
    * **Cause:** The tool cannot locate your credentials file.
    * **Solution:** Verify that `credentials.json` is inside the `credentials/` folder and that the path in `config.yaml` matches.

5.  **Error: invalid_scope (OAuth only)**
    * **Cause:** The OAuth token was created with a different set of scopes.
    * **Solution:** Delete `token.json` from the project directory and re-run the auditor. You will be prompted to re-authenticate.

6.  **Error: Input should be a valid dictionary**
    * **Cause:** Syntax error in `config.yaml`.
    * **Solution:** Check for typos. Ensure no empty brackets `[]` where the tool expects a dictionary `{}`.

7.  **Chrome Policy warnings: "root OU ID unavailable"**
    * **Cause:** The org unit lookup failed, usually because the Admin SDK API is not enabled or the account lacks permissions.
    * **Solution:** Ensure the Admin SDK API is enabled and the service account/subject has Super Admin privileges.

8.  **Authentication Fails / Stuck on Login (OAuth only)**
    * **Cause:** Your browser might be remembering a different Google account session.
    * **Solution:** Open an Incognito Window, manually paste the URL provided by the terminal, and log in with your Admin credentials.

---

If you require further assistance, please capture a screenshot of your terminal error and send it to our support team.
