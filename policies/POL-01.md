# POL-01 — Password & Authentication Policy

*Effective: 2025-09-01. Owner: Identity & Access Management team.*

**1.1** Standard user passwords must be at least 14 characters, contain three of four character classes, and not match any of the previous 12 passwords.

**1.2** Standard accounts rotate passwords annually. Privileged accounts (domain admins, root, DBA) rotate every 90 days.

**1.3** Multi-factor authentication (MFA) is mandatory for every corporate application and is enforced via Okta. Acceptable second factors: Okta Verify push, FIDO2 security key, or TOTP.

**1.4** Accounts are locked after 5 consecutive failed login attempts. Self-service unlock is available after 15 minutes via the password portal; otherwise contact the Service Desk.

**1.5** 1Password Enterprise is the sanctioned password manager. Storing corporate credentials in browsers, sticky notes, or personal password managers is prohibited.

**1.6** Privileged users must additionally authenticate with a YubiKey 5 series hardware token. Soft tokens alone do not satisfy privileged access requirements.
