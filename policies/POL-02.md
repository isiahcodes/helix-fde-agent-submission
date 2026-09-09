# POL-02 — VPN & Remote Access Policy

*Effective: 2025-07-15. Owner: Network Security.*

**2.1** Cisco AnyConnect is the only approved VPN client. Personal VPNs (NordVPN, ExpressVPN, etc.) must not be installed on corporate endpoints.

**2.2** Split tunneling is disabled by policy. All traffic is routed through the corporate gateway and inspected by Zscaler.

**2.3** VPN sessions terminate after 12 hours of connection or 30 minutes of inactivity, whichever comes first.

**2.4** Public or untrusted Wi-Fi (hotels, cafés, airports) is permitted only when AnyConnect is active before any other traffic.

**2.5** Access is geo-restricted to the Approved Country List maintained by Network Security. Connecting from outside the list requires a Travel Exception ticket submitted at least 5 business days in advance. (Approved list includes US-East and EU-Central / Germany; Japan and Vietnam are not on the list.)

**2.6** Privileged remote access to production systems is brokered through CyberArk PAM. Direct SSH/RDP to production from a laptop is forbidden.
