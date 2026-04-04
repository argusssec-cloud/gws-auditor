# GWS Security Auditor - Complete Check Reference

## Overview

The GWS Security Auditor implements **202 security checks** across four frameworks:

| Framework | Full Name | Checks |
|-----------|-----------|-------:|
| **CIS** | CIS Google Workspace Foundations Benchmark v1.3.0 | 87 |
| **CISA** | CISA SCuBA Baselines for Google Workspace | 88 |
| **GOOGLE** | Google Security Checklist for Medium & Large Businesses | 23 |
| **OTHER** | Additional best-practice checks | 4 |
| | **Total** | **202** |

## Check Levels

- **L1 (Level 1)** -- 132 checks. Baseline security settings that should be applied to all organizations. Minimal performance impact, broad applicability.
- **L2 (Level 2)** -- 70 checks. Advanced security settings for organizations with higher security requirements. May restrict functionality or require additional configuration.

## Check Statuses

| Status | Meaning |
|--------|---------|
| **PASS** | Configuration meets the benchmark requirement |
| **FAIL** | Configuration does not meet the requirement |
| **WARN** | Partial compliance or potential issue detected |
| **ERROR** | Check could not complete due to an API or runtime error |
| **MANUAL** | Requires manual verification (cannot be fully automated) |
| **NOT_APPLICABLE** | Check does not apply to this environment |

---

## Directory

| ID | Title | Level | Source |
|----|-------|-------|--------|
| CIS-1.1.1 | Ensure more than one Super Admin account exists | L1 | CIS |
| CIS-1.1.2 | Ensure fewer than 4 Super Admin accounts exist | L1 | CIS |
| CIS-1.1.3 | Ensure Super Admin accounts are only used for admin tasks | L2 | CIS |
| CIS-1.2.1.1 | Ensure directory data is restricted from external access | L1 | CIS |

## Calendar

| ID | Title | Level | Source |
|----|-------|-------|--------|
| CIS-3.1.1.1.1 | Ensure external sharing for primary calendars is limited | L1 | CIS |
| CIS-3.1.1.1.2 | Ensure internal sharing for primary calendars is configured | L1 | CIS |
| CIS-3.1.1.1.3 | Ensure external invitations show warning | L1 | CIS |
| CIS-3.1.1.2.1 | Ensure external sharing for secondary calendars is limited | L1 | CIS |
| CIS-3.1.1.2.2 | Ensure internal sharing for secondary calendars is configured | L2 | CIS |
| CIS-3.1.1.3.1 | Ensure Calendar web offline access is disabled | L2 | CIS |
| GWS.CALENDAR.3.1 | Ensure Calendar Interop is disabled | L1 | CISA |
| GWS.CALENDAR.4.1 | Ensure paid appointment scheduling is disabled | L1 | CISA |
| ADD-23 | Ensure DLP rules are configured for Calendar | L2 | GOOGLE |

## Drive and Docs

| ID | Title | Level | Source |
|----|-------|-------|--------|
| CIS-3.1.2.1.1.1 | Ensure users are warned when sharing outside domain | L1 | CIS |
| CIS-3.1.2.1.1.2 | Ensure users cannot publish files publicly | L1 | CIS |
| CIS-3.1.2.1.1.3 | Ensure sharing is controlled by domain allowlists | L2 | CIS |
| CIS-3.1.2.1.1.4 | Ensure users are warned when sharing with allowlisted domains | L2 | CIS |
| CIS-3.1.2.1.1.5 | Ensure Access Checker limits file access | L1 | CIS |
| CIS-3.1.2.1.1.6 | Ensure only internal users can distribute content externally | L2 | CIS |
| CIS-3.1.2.1.2.1 | Ensure Shared Drive creation is controlled | L1 | CIS |
| CIS-3.1.2.1.2.2 | Ensure manager cannot override shared drive settings | L2 | CIS |
| CIS-3.1.2.1.2.3 | Ensure shared drive access is restricted to members | L1 | CIS |
| CIS-3.1.2.1.2.4 | Ensure viewers cannot download, print, or copy files | L2 | CIS |
| CIS-3.1.2.2.1 | Ensure offline access to Drive is disabled | L2 | CIS |
| CIS-3.1.2.2.2 | Ensure Desktop access to Drive is disabled | L2 | CIS |
| CIS-3.1.2.2.3 | Ensure Drive add-ons are disabled | L2 | CIS |
| GWS.DRIVEDOCS.1.2 | Ensure receiving files from non-allowlisted domains is disabled | L1 | CISA |
| GWS.DRIVEDOCS.1.4 | Ensure sharing with non-Google accounts is disabled | L1 | CISA |
| GWS.DRIVEDOCS.1.5 | Ensure 'anyone with the link' sharing is disabled | L1 | CISA |
| GWS.DRIVEDOCS.1.8 | Ensure default access for new items is 'private to owner' | L1 | CISA |
| GWS.DRIVEDOCS.3.1 | Ensure security updates for files are applied | L1 | CISA |
| GWS.DRIVEDOCS.4.1 | Ensure Drive SDK is disabled | L1 | CISA |
| ADD-24 | Ensure AI-powered data classification is enabled for Drive | L2 | GOOGLE |
| ADD-25 | Ensure Drive trust rules are configured | L2 | GOOGLE |

## Gmail

| ID | Title | Level | Source |
|----|-------|-------|--------|
| CIS-3.1.3.1.1 | Ensure mail delegation is disabled | L1 | CIS |
| CIS-3.1.3.1.2 | Ensure offline Gmail is disabled | L2 | CIS |
| CIS-3.1.3.2.1 | Ensure DKIM is enabled for all domains | L1 | CIS |
| CIS-3.1.3.2.2 | Ensure SPF records are configured for all domains | L1 | CIS |
| CIS-3.1.3.2.3 | Ensure DMARC records are configured for all domains | L1 | CIS |
| CIS-3.1.3.3.1 | Ensure quarantine admin notifications are enabled | L2 | CIS |
| CIS-3.1.3.4.1.1 | Ensure encrypted attachment protection is enabled | L1 | CIS |
| CIS-3.1.3.4.1.2 | Ensure script attachment protection is enabled | L1 | CIS |
| CIS-3.1.3.4.1.3 | Ensure anomalous attachment protection is enabled | L1 | CIS |
| CIS-3.1.3.4.2.1 | Ensure shortened URL identification is enabled | L1 | CIS |
| CIS-3.1.3.4.2.2 | Ensure linked image scanning is enabled | L1 | CIS |
| CIS-3.1.3.4.2.3 | Ensure warning for untrusted links is enabled | L1 | CIS |
| CIS-3.1.3.4.3.1 | Ensure domain spoofing protection is enabled | L1 | CIS |
| CIS-3.1.3.4.3.2 | Ensure employee name spoofing protection is enabled | L1 | CIS |
| CIS-3.1.3.4.3.3 | Ensure inbound domain spoofing protection is enabled | L1 | CIS |
| CIS-3.1.3.4.3.4 | Ensure unauthenticated email protection is enabled | L1 | CIS |
| CIS-3.1.3.4.3.5 | Ensure Groups inbound spoofing protection is enabled | L1 | CIS |
| CIS-3.1.3.5.1 | Ensure POP and IMAP access is disabled | L1 | CIS |
| CIS-3.1.3.5.2 | Ensure automatic email forwarding is disabled | L1 | CIS |
| CIS-3.1.3.5.3 | Ensure per-user outbound gateways are disabled | L1 | CIS |
| CIS-3.1.3.5.4 | Ensure external recipient warnings are enabled | L1 | CIS |
| CIS-3.1.3.6.1 | Ensure enhanced pre-delivery message scanning is enabled | L1 | CIS |
| CIS-3.1.3.6.2 | Ensure spam filters are not bypassed for internal senders | L1 | CIS |
| CIS-3.1.3.7.1 | Ensure comprehensive mail storage is enabled | L2 | CIS |
| CIS-3.1.3.7.2 | Ensure secure TLS connection is enforced | L1 | CIS |
| GWS.GMAIL.4.3 | Ensure DMARC alignment mode is strict | L1 | CISA |
| GWS.GMAIL.4.4 | Ensure DMARC reporting is configured | L1 | CISA |
| GWS.GMAIL.8.1 | Ensure user email uploads are disabled | L1 | CISA |
| GWS.GMAIL.10.1 | Ensure Google Workspace Sync is disabled | L1 | CISA |
| GWS.GMAIL.14.1 | Ensure email allowlist is not used | L1 | CISA |
| ADD-02 | Ensure Security Sandbox is enabled for Gmail | L1 | OTHER |
| ADD-05 | Ensure MX records point to Google | L1 | GOOGLE |
| ADD-06 | Ensure inbound gateway SPF configuration is correct | L2 | GOOGLE |
| ADD-07 | Ensure TLS is enforced for partner domains | L2 | GOOGLE |
| ADD-12 | Ensure DLP rules are configured for Gmail | L1 | GOOGLE |
| ADD-22 | Ensure data classification labels are enabled for Gmail | L1 | GOOGLE |
| ADD-26 | Ensure CSE is enabled for Gmail | L2 | GOOGLE |

## Google Chat

| ID | Title | Level | Source |
|----|-------|-------|--------|
| CIS-3.1.4.1.1 | Ensure external file sharing in Chat is disabled | L2 | CIS |
| CIS-3.1.4.1.2 | Ensure internal file sharing in Chat is disabled | L2 | CIS |
| CIS-3.1.4.2.1 | Ensure external chat is restricted to allowed domains | L1 | CIS |
| CIS-3.1.4.3.1 | Ensure external spaces are restricted | L1 | CIS |
| CIS-3.1.4.4.1 | Ensure Chat app installation is disabled | L2 | CIS |
| CIS-3.1.4.4.2 | Ensure incoming webhooks are disabled | L2 | CIS |
| GWS.CHAT.1.1 | Ensure Chat history is enabled | L1 | CISA |
| GWS.CHAT.1.2 | Ensure users cannot change Chat history setting | L1 | CISA |
| GWS.CHAT.5.1 | Ensure Chat content reporting is enabled | L1 | CISA |
| ADD-04 | Ensure Chat space history is enabled | L2 | OTHER |

## Google Meet

| ID | Title | Level | Source |
|----|-------|-------|--------|
| GWS.MEET.1.1 | Ensure external users must ask to join meetings | L1 | CISA |
| GWS.MEET.2.1 | Ensure non-GWS tenant meeting access is disabled | L1 | CISA |
| GWS.MEET.3.1 | Ensure host management is enabled | L1 | CISA |
| GWS.MEET.4.1 | Ensure external participant warning is enabled | L1 | CISA |
| GWS.MEET.5.1 | Ensure incoming calls are restricted to organization | L1 | CISA |
| GWS.MEET.6.1 | Ensure automatic recording is disabled | L1 | CISA |
| GWS.MEET.6.2 | Ensure automatic transcription is disabled | L1 | CISA |
| ADD-03 | Ensure Meet joining controls are configured | L1 | OTHER |
| ADD-17 | Ensure AI note-taking in Meet requires host approval | L2 | GOOGLE |
| ADD-27 | Ensure Meet compliance recording is configured | L2 | GOOGLE |

## Groups

| ID | Title | Level | Source |
|----|-------|-------|--------|
| CIS-3.1.6.1 | Ensure external Groups access is private | L1 | CIS |
| CIS-3.1.6.2 | Ensure group creation is restricted to admins | L1 | CIS |
| CIS-3.1.6.3 | Ensure group conversation viewing is restricted | L2 | CIS |
| CIS-3.1.8.1 | Ensure external Google Groups is disabled | L2 | CIS |
| GWS.GROUPS.1.3 | Ensure external posting to groups is disabled | L1 | CISA |
| GWS.GROUPS.4.1 | Ensure groups cannot be hidden from directory | L1 | CISA |

## Sites

| ID | Title | Level | Source |
|----|-------|-------|--------|
| CIS-3.1.7.1 | Ensure Google Sites creation is disabled | L2 | CIS |

## Marketplace

| ID | Title | Level | Source |
|----|-------|-------|--------|
| CIS-3.1.9.1.1 | Ensure Marketplace apps are restricted | L1 | CIS |

## Security (Authentication & Identity)

| ID | Title | Level | Source |
|----|-------|-------|--------|
| CIS-4.1.1.1 | Ensure 2-Step Verification is enforced for all admins | L1 | CIS |
| CIS-4.1.1.2 | Ensure hardware security keys are required for admins | L2 | CIS |
| CIS-4.1.1.3 | Ensure 2-Step Verification is enforced for all users | L1 | CIS |
| CIS-4.1.2.1 | Ensure super admin account recovery is disabled | L1 | CIS |
| CIS-4.1.2.2 | Ensure user account recovery is enabled | L1 | CIS |
| CIS-4.1.3.1 | Ensure Advanced Protection Program is available | L2 | CIS |
| CIS-4.1.4.1 | Ensure login challenges are enforced | L1 | CIS |
| CIS-4.1.5.1 | Ensure password policy is enhanced | L1 | CIS |
| CIS-4.2.6.1 | Ensure less secure app access is disabled | L1 | CIS |
| GWS.COMMONCONTROLS.1.3 | Ensure SMS/Voice MFA methods are disabled | L1 | CISA |
| GWS.COMMONCONTROLS.1.4 | Ensure MFA enrollment period is configured | L1 | CISA |
| GWS.COMMONCONTROLS.1.5 | Ensure 'trust this device' is disabled | L1 | CISA |
| GWS.COMMONCONTROLS.7.1 | Ensure conflicting account management is configured | L1 | CISA |
| GWS.COMMONCONTROLS.15.1 | Ensure data regions are configured | L2 | CISA |
| GWS.COMMONCONTROLS.17.1 | Ensure multi-party approval is enabled | L2 | CISA |
| ADD-01 | Ensure session length is 7 days or less | L1 | OTHER |
| ADD-08 | Ensure Password Alert is deployed | L2 | GOOGLE |
| ADD-09 | Ensure Google Takeout is restricted | L1 | GOOGLE |
| ADD-11 | Ensure client-side encryption is enabled | L2 | GOOGLE |
| ADD-16 | Ensure Apple Intelligence Writing Tools are disabled for Workspace | L2 | GOOGLE |
| ADD-18 | Ensure passkeys are enforced as primary authentication | L2 | GOOGLE |
| ADD-19 | Ensure Device Bound Session Credentials (DBSC) are enabled | L2 | GOOGLE |
| ADD-20 | Ensure Context-Aware Access is applied to OIDC apps | L2 | GOOGLE |
| ADD-21 | Ensure Multi-Party Approval covers Vault exports | L2 | GOOGLE |

## Gemini

| ID | Title | Level | Source |
|----|-------|-------|--------|
| ADD-13 | Ensure Gemini features in Workspace apps are controlled | L1 | GOOGLE |
| ADD-14 | Ensure Gemini in Chrome is disabled | L2 | GOOGLE |
| ADD-15 | Ensure Google Workspace Studio access is controlled | L2 | GOOGLE |

## Access Control

| ID | Title | Level | Source |
|----|-------|-------|--------|
| CIS-4.2.1.1 | Ensure third-party app access is restricted | L1 | CIS |
| CIS-4.2.1.2 | Ensure third-party apps are reviewed | L2 | CIS |
| CIS-4.2.1.3 | Ensure internal app API access is controlled | L2 | CIS |
| CIS-4.2.1.4 | Ensure domain-wide delegation is reviewed | L2 | CIS |
| CIS-4.2.2.1 | Ensure geo-blocking is configured | L2 | CIS |
| CIS-4.2.3.1 | Ensure DLP policies are configured for Drive | L1 | CIS |
| CIS-4.2.4.1 | Ensure session control is configured | L2 | CIS |
| CIS-4.2.5.1 | Ensure cloud session control is configured | L2 | CIS |

## Reporting

| ID | Title | Level | Source |
|----|-------|-------|--------|
| CIS-5.1.1.1 | Ensure App Usage Activity Report is reviewed | L1 | CIS |
| CIS-5.1.1.2 | Ensure Security Investigation Tool is used | L1 | CIS |
| GWS.COMMONCONTROLS.14.1 | Ensure audit logging is enabled | L1 | CISA |
| ADD-10 | Ensure Vault activity auditing is enabled | L2 | GOOGLE |

## Alert Rules

| ID | Title | Level | Source |
|----|-------|-------|--------|
| CIS-6.1 | Ensure alert for user password change is configured | L1 | CIS |
| CIS-6.2 | Ensure alert for government-backed attacks is configured | L1 | CIS |
| CIS-6.3 | Ensure alert for suspicious activity is configured | L1 | CIS |
| CIS-6.4 | Ensure alert for admin privilege grant is configured | L1 | CIS |
| CIS-6.5 | Ensure alert for suspicious programmatic login is configured | L1 | CIS |
| CIS-6.6 | Ensure alert for suspicious login is configured | L1 | CIS |
| CIS-6.7 | Ensure alert for leaked password is configured | L1 | CIS |
| CIS-6.8 | Ensure alert for employee spoofing is configured | L1 | CIS |
