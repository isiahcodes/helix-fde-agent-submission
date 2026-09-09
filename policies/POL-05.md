# POL-05 — Data Classification & Handling Policy

*Effective: 2025-04-01. Owner: Data Governance.*

**5.1** Helix data is classified into four tiers: Public, Internal, Confidential, and Restricted. Every document inherits the highest tier of any field it contains.

**5.2** Restricted data (PHI, payment card data, source code for revenue-critical systems) must be encrypted both at rest and in transit, and may only reside in approved geographies (US-East, EU-Central).

**5.3** Confidential data may not be sent to external recipients without a Data Loss Prevention (DLP) exception. The DLP exception process requires data owner approval and is valid for 30 days.

**5.4** EU personal data is subject to GDPR controls; transfer outside the EEA requires Standard Contractual Clauses on file.

**5.5** Retention follows the published Records Retention Schedule. Default for unclassified business records is 7 years; PHI is 10 years; payment data is purged at 13 months.

**5.6** Auto-forwarding corporate email to any external address (including personal Gmail) is technically blocked and policy-prohibited.
