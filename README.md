
# MITRE-KQL-Library (Windows)

Technique-aligned **Microsoft Defender XDR Advanced Hunting** queries for the **MITRE ATT&CK® Enterprise (Windows)** matrix. Queries are **behavioral** and **do not rely on AlertInfo/AlertEvidence/AlertID**; they operate directly on raw telemetry tables (endpoint, email, identity, cloud apps).

## Structure
```
MITRE-KQL-Library/
  global/Globals.kql
  InitialAccess/*.kql
  Execution/*.kql
  Persistence/*.kql
  PrivilegeEscalation/*.kql
  DefenseEvasion/*.kql
  CredentialAccess/*.kql
  Discovery/*.kql
  LateralMovement/*.kql
  Collection/*.kql
  CommandAndControl/*.kql
  Exfiltration/*.kql
  Impact/*.kql
  Email/*.kql
  Identity/*.kql
```

## Usage
1. Open **Microsoft Defender XDR > Advanced hunting**.
2. Option A: Paste **global/Globals.kql** at the top of your session and then run any query.
   //Option B: Add the minimal `let lookback = 14d;` etc. to an individual query for standalone use. ( I removed _lookback_ from the queries - but the other parameters are valid for option A.)
3. Tune allowlists/thresholds for your environment (e.g., `allowRemotePorts`, `browserNames`).
4. Convert hunts you like into **Custom detections** with appropriate response actions.

## Prerequisites
- **Endpoint tables** (e.g., `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceImageLoadEvents`, `DeviceEvents`).
- **Email & collaboration tables** for email-centric techniques (e.g., `EmailEvents`, `EmailPostDeliveryEvents`).
- **Identity tables** (e.g., `IdentityLogonEvents`) for lateral movement and brute-force patterns.
- **Cloud app** telemetry (`CloudAppEvents`) for SaaS exfiltration.

> Advanced Hunting retains ~30 days; for longer retention, forward via **Streaming API**/**Microsoft Sentinel**.

## References
- Microsoft Defender XDR Advanced Hunting table references on Microsoft Learn.
- MITRE ATT&CK® Enterprise (Windows) matrix.

MIT License
