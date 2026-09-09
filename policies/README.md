# Helix policy pack (authorized knowledge only)

POL-01 through POL-10 are the **only** source of truth. The agent must cite stable ids (`POL-04 §4.6`) and refuse to act from prior knowledge.

These ten documents are the authorized corpus in full.

When implementation starts, split each policy into structured sections:

```json
{
  "policy_id": "POL-04",
  "section": "4.6",
  "span": "POL-04 §4.6",
  "owner": "IT Procurement",
  "effective": "2025-03-10",
  "text": "Local admin rights are removed by default. Time-bound admin elevation can be requested through Make-Me-Admin for a maximum of 60 minutes per session. Permanent local admin is not self-service and requires an Endpoint Engineering exception."
}
```

| ID | Title | Owner |
| --- | --- | --- |
| POL-01 | Password & Authentication | Identity & Access Management |
| POL-02 | VPN & Remote Access | Network Security |
| POL-03 | Acceptable Use | Information Security |
| POL-04 | Software Installation & Procurement | IT Procurement |
| POL-05 | Data Classification & Handling | Data Governance |
| POL-06 | BYOD | Endpoint Engineering |
| POL-07 | Email & Communication Security | Messaging Security |
| POL-08 | Hardware Request & Asset Management | IT Asset Management |
| POL-09 | Security Incident Reporting | Security Operations Center |
| POL-10 | Access Provisioning & Deprovisioning | Identity & Access Management |

Onboarding a customer policy #11 means adding a file here, conflict pointers against POL-01 to POL-10, and five gold tickets. It does not mean forking the orchestrator.
