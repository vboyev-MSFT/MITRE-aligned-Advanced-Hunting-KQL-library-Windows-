# MITRE-Aligned Advanced Hunting KQL Library for Windows

## Overview

This repository contains **Kusto Query Language (KQL)** queries for **Microsoft Defender Advanced Hunting**, organized around the **MITRE ATT&CK® framework** and focused on **Windows endpoint telemetry**.

The purpose of this library is to help security practitioners move quickly from adversary behavior to actionable hunting logic.

Use this repository to:

- Hunt for suspicious Windows endpoint activity
- Validate MITRE ATT&CK coverage in Microsoft Defender XDR
- Investigate alerts and incidents using endpoint telemetry
- Build repeatable detection engineering workflows
- Convert high-confidence hunting logic into custom detections

This repository is designed for security analysts, threat hunters, detection engineers, cloud security architects, and defenders working with Microsoft Defender for Endpoint and Microsoft Defender XDR.

---

## Quick Start

1. Open the **Microsoft Defender portal**.
2. Go to **Hunting** > **Advanced Hunting**.
3. Choose a query from the relevant MITRE tactic folder.
4. Paste the query into Advanced Hunting.
5. Review and tune any environment-specific values.
6. Run the query.
7. Investigate returned results.
8. If the logic produces high-confidence signal, consider converting it into a custom detection.

---

## Repository Goals

This project is intended to provide practical, operator-ready hunting content rather than a loose collection of disconnected KQL snippets.

The core goals are:

- **MITRE alignment** — map queries to adversary tactics and techniques.
- **Defender-native execution** — use Microsoft Defender Advanced Hunting tables and syntax.
- **Operational usability** — make queries easy to run, tune, and interpret.
- **Detection engineering readiness** — support promotion from hunting logic to detection logic where appropriate.
- **Repeatable investigation workflows** — help analysts understand what to do after a query returns results.

---

## Prerequisites

Before using this repository, confirm that you have the following:

- Access to **Microsoft Defender XDR**
- Access to **Advanced Hunting**
- Permission to query relevant endpoint telemetry
- Microsoft Defender for Endpoint onboarded on Windows devices
- Basic familiarity with KQL pipeline syntax
- Basic understanding of common Defender Advanced Hunting tables

Commonly used tables may include:

- `DeviceProcessEvents`
- `DeviceFileEvents`
- `DeviceRegistryEvents`
- `DeviceNetworkEvents`
- `DeviceLogonEvents`
- `DeviceImageLoadEvents`
- `DeviceEvents`
- `AlertInfo`
- `AlertEvidence`

Not every query uses every table. Review the query header and body before running it.

---

## How the Repository Is Organized

Queries are organized by MITRE ATT&CK tactic.

Recommended folder structure:

```text
/
├── Execution/
├── Persistence/
├── PrivilegeEscalation/
├── DefenseEvasion/
├── CredentialAccess/
├── Discovery/
├── LateralMovement/
├── Collection/
├── CommandAndControl/
├── Exfiltration/
├── Impact/
└── Utilities/
```

Each query should be placed in the folder that best matches its primary MITRE tactic. If a query maps to multiple tactics or techniques, document that in the query header.

---

## How to Use These Queries

### 1. Start with the investigation objective

Do not begin by randomly running queries. Start with the question you are trying to answer.

Examples:

- Did a suspicious script interpreter execute on a Windows endpoint?
- Are there signs of persistence through registry run keys?
- Did a process create unusual outbound network connections?
- Is there evidence of credential dumping behavior?
- Are administrative tools being used in unexpected contexts?

Once the objective is clear, select the query that best maps to that behavior.

---

### 2. Choose the relevant MITRE tactic

Use MITRE ATT&CK as the navigation model.

Examples:

- **Execution** — suspicious command, script, or binary execution
- **Persistence** — startup folders, services, scheduled tasks, registry autostart locations
- **Privilege Escalation** — suspicious token, service, or elevation behavior
- **Defense Evasion** — tampering, obfuscation, disabling controls, suspicious renaming
- **Credential Access** — credential dumping, LSASS access, browser credential access
- **Discovery** — enumeration of users, groups, domain, network, or system configuration
- **Lateral Movement** — remote execution, admin shares, remote services
- **Command and Control** — suspicious outbound communication patterns
- **Exfiltration** — unusual archive, staging, or outbound transfer behavior
- **Impact** — destructive actions, encryption behavior, recovery inhibition

---

### 3. Review the query header

Every production-ready query should include a header similar to the following:

```kql
// Title: Suspicious PowerShell Download Activity
// Description: Identifies PowerShell command lines containing common download-related functions or web client usage.
// MITRE ATT&CK: T1059.001 - PowerShell
// Tactic: Execution
// Platform: Windows
// Data sources: DeviceProcessEvents
// Use case: Hunting / detection candidate
// False positives: Administrative scripts, software deployment tools, automation frameworks
// Tuning: Add known-good script paths, management servers, or signed administrative tooling
```

The header tells you what the query is intended to find, where it should run, and how to interpret likely noise.

---

### 4. Run the query in Advanced Hunting

Copy the query into **Advanced Hunting** and run it against your selected portal time range.

This repository intentionally avoids hardcoding a time window unless a query requires a specific lookback for logic such as first-seen analysis, baseline comparison, or period-over-period correlation.

In most cases, set the time range in the Defender portal UI rather than adding a fixed line such as:

```kql
| where Timestamp > ago(7d)
```

Use explicit time filters only when the query logic depends on them.

---

### 5. Interpret results carefully

A returned row is not automatically malicious.

Treat results as investigative leads unless the query explicitly states that it is a high-confidence detection candidate.

When reviewing results, look for:

- Unusual parent-child process relationships
- Rare process names or file paths
- Suspicious command-line arguments
- Newly observed behavior
- Unexpected user context
- Activity on sensitive endpoints
- Connections to unusual remote destinations
- Repetition across multiple devices
- Correlation with alerts or incident evidence

---

### 6. Pivot for context

After a query returns results, pivot into related telemetry.

Common pivots include:

- From process execution to file activity using `DeviceFileEvents`
- From process execution to network activity using `DeviceNetworkEvents`
- From file creation to process lineage using `InitiatingProcess*` fields
- From endpoint behavior to alerts using `AlertInfo` and `AlertEvidence`
- From local activity to user context using `DeviceLogonEvents`

Useful fields for pivoting often include:

- `DeviceId`
- `DeviceName`
- `Timestamp`
- `ProcessCommandLine`
- `InitiatingProcessCommandLine`
- `InitiatingProcessFileName`
- `InitiatingProcessParentFileName`
- `SHA256`
- `RemoteIP`
- `RemoteUrl`
- `AccountName`
- `AccountSid`

---

## Query Types

Queries in this repository should be labeled by operational purpose.

### Hunting Query

Exploratory logic intended to find suspicious or unusual behavior. These queries may return benign results and usually require analyst review.

### Detection Candidate

Higher-confidence logic that may be suitable for conversion into a custom detection after validation and tuning.

### Baseline Query

A query used to establish normal activity in an environment before writing stricter detection logic.

### Enrichment Query

A query used to add context during an investigation, such as process lineage, file details, network connections, or related alerts.

### Utility Query

Reusable helper logic, lookup logic, or investigative snippets that support other hunts.

---

## Query Anatomy

Most queries follow the same basic pipeline structure.

Example:

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("DownloadFile", "DownloadString", "WebClient", "Invoke-WebRequest")
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp desc
```

### Table selection

The first line identifies the telemetry source.

Example:

```kql
DeviceProcessEvents
```

Use the table that best represents the behavior you are investigating.

### Filtering

`where` clauses narrow the dataset.

Example:

```kql
| where FileName in~ ("powershell.exe", "pwsh.exe")
```

Use filters to isolate relevant activity and reduce noise.

### Matching behavior

String operators such as `has`, `has_any`, `contains`, `startswith`, and `endswith` identify behavioral indicators.

Prefer token-aware operators such as `has` or `has_any` when appropriate. Use broader operators such as `contains` only when tokenized matching may miss the target pattern.

### Projection

`project` controls which columns are returned.

Example:

```kql
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

Return enough context for triage without overwhelming the analyst.

### Sorting

Use sorting to make recent or highest-risk activity easier to review.

Example:

```kql
| order by Timestamp desc
```

---

## Tuning Guidance

Most queries require tuning before production use.

Common tuning options include:

- Add known-good administrative tools
- Exclude approved software deployment paths
- Exclude expected management servers
- Scope to specific device groups
- Scope to high-value assets
- Add signer or certificate checks where available
- Adjust thresholds for your environment
- Suppress known automation accounts
- Filter expected internal domains or update services

Example allowlist pattern:

```kql
let KnownAdminTools = dynamic([
    "approved-tool.exe",
    "trusted-script.ps1"
]);
DeviceProcessEvents
| where FileName !in~ (KnownAdminTools)
```

Keep allowlists explicit and review them periodically. Overbroad exclusions can remove meaningful signal.

---

## False Positive Review

Before promoting a query into a detection, review expected sources of benign activity.

Common false positive sources include:

- IT administration
- Software deployment
- Endpoint management tooling
- Vulnerability scanners
- Backup agents
- Monitoring tools
- Developer tooling
- Security testing
- Red team activity
- Lab activity

For each query, document known false positive patterns in the query header or adjacent notes.

---

## What to Do When a Query Returns Results

Use the following triage workflow.

### 1. Validate the behavior

Ask:

- Is the action expected on this device?
- Is the user expected to perform this activity?
- Is the process signed and located in a normal path?
- Does the command line match known administrative behavior?
- Has this behavior appeared before?

### 2. Review process lineage

Investigate:

- Parent process
- Child process
- Command line
- User context
- Integrity level, if available
- File path
- Hash

### 3. Check surrounding activity

Look before and after the suspicious event.

Useful pivots:

- Files created or modified around the same time
- Network connections from the same process
- Related logon activity
- Registry changes
- Service creation
- Scheduled task creation
- Alerts involving the same device, user, file, or IP address

### 4. Determine disposition

Classify the result as one of the following:

- Benign expected activity
- Benign but noisy
- Suspicious and requires monitoring
- Confirmed malicious
- Inconclusive and requires more data

### 5. Take response action if needed

Depending on severity and confidence, response actions may include:

- Initiate incident investigation
- Isolate device
- Collect investigation package
- Block file hash or indicator
- Disable compromised account
- Remove persistence mechanism
- Escalate to incident response
- Convert query into custom detection logic

---

## Converting Hunting Queries to Custom Detections

Some queries may be suitable for scheduled detection after validation.

Before converting a hunting query into a custom detection, confirm:

- The signal is high-confidence
- False positives are understood
- Required columns are returned
- Entity fields are available for alert evidence
- Query performance is acceptable
- Suppression logic is documented
- Response actions are clear

Detection candidates should be stricter than exploratory hunting queries.

A good detection candidate should answer:

- What behavior is being detected?
- Why is it suspicious?
- What MITRE technique does it map to?
- What are common false positives?
- What should the analyst do next?

---

## Query Development Standards

All new queries should follow these standards.

### Required query header

```kql
// Title:
// Description:
// MITRE ATT&CK:
// Tactic:
// Technique:
// Platform:
// Data sources:
// Query type:
// Expected output:
// False positives:
// Tuning guidance:
// Analyst action:
```

### Required query qualities

Queries should be:

- Readable
- Commented where logic is non-obvious
- Scoped to the relevant behavior
- Conservative with expensive operations
- Clear about expected output
- Useful for investigation or detection

### Preferred formatting

- One pipeline operator per line
- Consistent indentation for `project`, `summarize`, and dynamic lists
- Use meaningful column aliases
- Keep comments concise and useful
- Place reusable values in `let` statements where appropriate

Example:

```kql
let SuspiciousScriptHosts = dynamic([
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe"
]);
DeviceProcessEvents
| where FileName in~ (SuspiciousScriptHosts)
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## Performance Guidance

Advanced Hunting queries should be written with performance in mind.

Recommended practices:

- Filter early
- Project only needed columns
- Avoid unnecessary joins
- Use `has` and `has_any` when token-based matching is sufficient
- Use `contains` only when needed
- Avoid broad wildcard-style logic when a targeted match works
- Summarize only after filtering
- Use `let` statements for reusable lists or subqueries
- Test query performance before operationalizing detection logic

---

## Naming Convention

Recommended file naming pattern:

```text
<Tactic>-<TechniqueID>-<ShortDescription>.kql
```

Examples:

```text
Execution-T1059.001-Suspicious-PowerShell-Download.kql
Persistence-T1060-Registry-Run-Key-Modification.kql
CredentialAccess-T1003-LSASS-Access.kql
DefenseEvasion-T1562.001-Defender-Tampering.kql
```

Use clear names that describe the behavior being hunted.

---

## MITRE ATT&CK Mapping

Each query should include MITRE mapping in the header.

Recommended format:

```text
MITRE ATT&CK: T1059.001 - PowerShell
Tactic: Execution
Technique: Command and Scripting Interpreter: PowerShell
```

Some behaviors may map to multiple tactics or techniques. In those cases, include all relevant mappings and identify the primary one.

Example:

```text
Primary: T1059.001 - PowerShell
Secondary: T1105 - Ingress Tool Transfer
```

---

## Example Investigation Workflow

### Scenario: Suspicious PowerShell download behavior

1. Run the relevant Execution query.
2. Review returned PowerShell command lines.
3. Identify whether the command downloaded content from an external source.
4. Pivot to network telemetry using the device, process, or timestamp.
5. Check file creation events after the download.
6. Review process lineage to determine what launched PowerShell.
7. Determine whether the activity was expected administration, automation, or suspicious execution.
8. If malicious or high-confidence suspicious, escalate and consider detection conversion.

---

## Recommended Analyst Review Checklist

When reviewing query results, capture:

- Device name
- User account
- Timestamp
- Process name
- Full command line
- Parent process
- File path
- SHA256 or other hash
- Remote IP or URL, if applicable
- Related alerts
- Initial disposition
- Follow-up action

---

## Limitations

These queries are only as useful as the telemetry available in your environment.

Potential limitations include:

- Device not onboarded to Microsoft Defender for Endpoint
- Missing or delayed telemetry
- Query permissions that restrict table access
- Environmental noise
- Legitimate administrative behavior that resembles attacker behavior
- MITRE mappings that represent best-fit behavior rather than perfect one-to-one classification

A query returning no results does not prove the behavior did not occur. It only means the query did not find matching telemetry within the selected scope and available data.

---

## Contribution Guidelines

Contributions are welcome when they improve detection value, clarity, or usability.

A useful contribution should include:

- Query file
- MITRE mapping
- Description
- Data source table or tables
- Expected results
- False positive notes
- Tuning guidance
- Analyst action guidance

Avoid submitting queries that are:

- Untested
- Undocumented
- Overly broad
- Environment-specific without explanation
- Duplicative of existing content without improvement

---

## Disclaimer

This repository provides hunting and detection engineering content for defensive security operations. Queries may require tuning before use in production environments. Validate results before taking response actions.

---

## Summary

This repository is intended to help defenders:

- Understand adversary behavior through MITRE ATT&CK
- Execute practical hunts in Microsoft Defender Advanced Hunting
- Investigate suspicious Windows endpoint activity
- Tune logic for real environments
- Promote validated hunts into repeatable detections

The best use of this library is not simply running queries. The best use is building a disciplined workflow:

```text
Behavior -> Query -> Results -> Context -> Disposition -> Detection or Response
```
