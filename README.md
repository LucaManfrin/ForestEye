# ForestEye
**Active Directory security assessment and incident-response visibility, packaged as a portable HTML dashboard.**

ForestEye is a PowerShell-based auditing tool designed to collect security-relevant information from a Microsoft Active Directory environment. Run from a domain controller, it examines users, computer accounts, domain configuration, trusts, password policies, Active Directory permissions, Group Policy Objects, and local audit policy. It exports the results into structured CSV files, optionally embeds them in a self-contained HTML dashboard, and bundles the output into a ZIP archive for offline review.

The objective is to help authorized administrators, defenders, and incident responders identify potentially risky configurations, unusual privileges, and areas requiring further investigation. **ForestEye reports indicators and configuration-based findings; it does not establish that an attack has occurred.**

> [!WARNING]
> **Authorization, legal responsibility, and production-use disclaimer**
>
> ForestEye is provided for **educational, research, auditing, and defensive security purposes only**. Use it **only** against systems and domains you own or for which you have explicit authorization. The author(s), maintainer(s), and distributor(s) **accept no responsibility or liability for illegal, unauthorized, abusive, or otherwise improper use**, or for damages, interruptions, data exposure, performance degradation, or other consequences arising from its use **in production or other environments**. Use is entirely at your own risk. This disclaimer does not supersede applicable law or create any warranty exclusion where prohibited by law.
>
> **Production environments are not guaranteed safe or supported.** ForestEye performs broad directory queries, ACL enumeration, SYSVOL reads, and report generation that may consume resources or expose sensitive infrastructure metadata. Validate the script in an isolated lab, obtain change/security approval, and assess its impact before considering execution on production infrastructure. Do not run it on production domain controllers without explicit authorization and an approved operational procedure.

## At a glance

| Feature | What ForestEye does | Output |
|---|---|---|
| User security | Detects risky account settings, privileged memberships, delegation, SPNs, SID history, and password-related indicators | `users.csv` |
| Computer security | Inventories endpoints and DCs, checks stale accounts, OS lifecycle, LAPS status, and delegation | `computers.csv` |
| Domain posture | Documents domain/DC/trust information, machine-account quota, privileged protection, and SYSVOL/NETLOGON write access | `domain.csv` |
| Password policy | Reviews default domain policy and fine-grained password policies | `policy.csv` |
| AD permissions | Prioritizes potentially dangerous owners and access control entries across selected high-value objects | `acl.csv` |
| Group Policy | Inventories GPOs, their links and owners, and scans selected configuration files for security concerns | `gpo.csv` |
| Audit configuration | Reads the **local machine's** advanced audit policy with `auditpol` | `auditpolicy.csv` (conditional) |
| HTML reporting | Injects CSV text into a compatible HTML template for offline inspection | `ForestEye.html` (conditional) |

## Requirements and permissions

- **Platform:** Windows PowerShell on Windows, with access to an Active Directory domain. The script is intended to run **on a domain controller**.
- **Modules:** The `ActiveDirectory` PowerShell module is mandatory (`#Requires -Module ActiveDirectory`). The `GroupPolicy` module and `Get-GPO` cmdlet are also needed for the GPO section; missing GPO functionality is handled as a section failure rather than validated during pre-flight.
- **Account:** The script's header specifies **Domain Admin** privileges. Some directory data may be obtainable with fewer permissions, but limited rights can produce incomplete results. Do not assume lower-privilege execution has been validated.
- **Elevation:** Open PowerShell using **Run as Administrator** to collect `auditpolicy.csv`. Being a member of Domain Admins does not necessarily provide an elevated local security token.
- **Connectivity:** Reachable AD services, DNS, and the SYSVOL/NETLOGON shares; access to the relevant directory naming contexts and policy files.
- **Storage:** Write access to the output path and sufficient free disk space for CSV files, the rendered dashboard, and a compressed archive.

**Important:** ForestEye does not run as a scheduled service, deploy agents, perform password cracking, or change AD object permissions. Its main assessment operations read configuration and permissions; it **does** create temporary and report files and may remove its generated output directory after successfully creating the ZIP.

## Quick start

1. Copy `ForestEye.ps1` to an authorized domain controller. To enable automatic reporting, place a compatible `ForestEye.html` beside it.
2. Launch **Windows PowerShell as Administrator** with the necessary domain privileges.
3. Run a standard collection:

   ```powershell
   .\ForestEye.ps1
   ```

4. Find the ZIP file at the location printed at the end of the run. Extract it and, if dashboard generation succeeded, open `ForestEye.html` in a browser.
5. Validate significant findings in AD and against your organization's approved baselines before taking action.

To choose an output location:

```powershell
.\ForestEye.ps1 -OutputPath 'D:\SecurityAudits\ForestEye-Review'
```

To limit the run to selected data sets:

```powershell
.\ForestEye.ps1 -SkipGPO -SkipACL
```

To adjust the ACL finding filter:

```powershell
.\ForestEye.ps1 -AclScoreThreshold 20
```

> The dashboard template is **not** part of `ForestEye.ps1`. If the compatible HTML file is unavailable, ForestEye still attempts to export the CSVs and create the ZIP; no populated HTML dashboard is produced.

## Command-line parameters

| Parameter | Default | Behavior |
|---|---|---|
| `-OutputPath` | `$env:SystemDrive\AD-Audit\yyyyMMdd-HHmmss` | Directory for intermediate and report files. The final ZIP is named by appending `.zip` to this path. |
| `-SkipUsers` | Off | Skips fresh user enumeration. Loads an existing `users.csv` from the output directory if one is present. |
| `-SkipComputers` | Off | Skips fresh computer enumeration; attempts to reuse an existing `computers.csv`. |
| `-SkipACL` | Off | Skips the full ACL scan; attempts to reuse `acl.csv`. |
| `-SkipGPO` | Off | Skips GPO enumeration; attempts to reuse `gpo.csv`. |
| `-AclScoreThreshold` | `12` | Minimum ACL score retained in the detailed ACL report. |

**Skip does not mean a complete offline run:** the script still executes its prerequisite checks, domain-wide preparation, domain and password-policy collection, audit-policy logic, IR checks, and packaging. Existing CSV reuse works only when the relevant files already exist in the chosen output directory; absent datasets will not be reconstructed. Avoid mixing files from different runs or domains.

## How a run works

```text
Prerequisite checks and domain discovery
              |
Privileged groups, replication rights, schema and security context
              |
 Users -> Computers -> Domain/DC/Trust -> Password policies
              |
       ACL assessment -> GPO assessment
              |
       Local audit policy -> IR warnings
              |
        Console summary and statistics
              |
   Optional CSV injection into HTML template
              |
          ZIP archive / cleanup
```

The console uses `[*]` for progress, `[+]` for success, `[!]` for warnings, and `[-]` for errors. Many individual directory lookups have their own error handling, so a completed run can still contain missing or partially collected data. Review console warnings rather than treating successful ZIP creation as proof of full coverage.

## Detailed section reference

### 0. Initialization, prerequisites, and shared discovery

**Purpose:** Confirm the execution environment and build shared lookup tables used by later assessments.

- Confirms that the Active Directory module is installed and a domain query succeeds.
- Creates/validates the output directory using a temporary `.write_test` file.
- Checks whether the current PowerShell token is elevated. Lack of elevation is non-fatal but prevents audit-policy export.
- Reads the domain, forest, root DSE, domain SID, and domain/configuration/schema naming contexts.
- Collects domain-controller names for delegation checks.
- Loads a built-in Windows OS end-of-support lookup table to classify operating systems.
- Enumerates a predefined set of privileged or security-sensitive AD groups, recursively resolves user membership, and marks direct versus nested membership.
- Inspects domain and configuration naming-context ACLs for selected replication-related extended rights (DCSync indicators).
- Checks the AdminSDHolder security descriptor for potentially unauthorized powerful access entries.
- Inspects membership of **Pre-Windows 2000 Compatible Access**, including broad principals such as Everyone, Anonymous, and Authenticated Users.
- Reads `ms-DS-MachineAccountQuota`, which influences who can create machine accounts.
- Resolves schema GUIDs for legacy/Windows LAPS and gMSA-related attributes, and discovers foreign security principals. Schema resolution prevents requests for attributes missing from a particular forest schema.

**Interpretation:** These shared checks provide context, not a comprehensive proof of exposure. A DCSync indicator depends on how access rights are combined and inherited; a suspicious AdminSDHolder entry requires manual authorization review. Built-in OS lifecycle dates are hardcoded and should be independently confirmed for the relevant product edition and support program.

### 1. Users (`users.csv`)

**Purpose:** Produce a domain-wide user inventory with security signals relevant to privilege, authentication, and account hygiene.

| Area | Representative fields / behavior |
|---|---|
| Identity and age | SAM name, SID, DN, description, creation date, last logon, password last set |
| Access and administration | Domain Admin flag, privileged groups, nesting paths, `adminCount`, apparent orphaned `adminCount=1` |
| Credential exposure indicators | Accounts with SPNs (`Kerberoastable`), preauthentication disabled (`ASREPRoastable`), `PasswordNotRequired`, reversible encryption |
| Password hygiene | Password-never-expires, passwords older than **365 days**, recently changed passwords within **72 hours**, expiry information |
| Delegation | Unconstrained or UAC-derived constrained-delegation indicators, privileged users lacking the sensitive/non-delegable flag |
| Trust and history | `SIDHistoryCount`, `SIDHistoryValues`, flagged privileged-looking RIDs, suspicious interdomain-trust UAC bit |
| Kerberos | Encryption flags, RC4/DES indicators, suspicious computer-style SPNs on user objects |
| Logon scope | Workstation restrictions and privileged users without them |
| Access-control context | Matching replication-rights findings (`HasDCSync`) |

**How to read the results:** `Kerberoastable=Yes` denotes an enabled user account with an SPN; it is **not** evidence of credential theft. `ASREPRoastable=Yes` denotes the preauthentication-disabled UAC bit. `AdminCountOrphan=Yes` is a heuristic; protected account history and group membership should be verified. `WeakKerberos` is based on the account's published encryption flags, not packet-level confirmation of negotiated encryption. The `HasDCSync` user flag reflects the script's trustee-name matching and is not a complete effective-permissions assessment.

**Last-logon caveat:** `LastLogonDate` derives from replicated timestamp data and can lag actual authentication. For forensic precision, inspect the non-replicated `lastLogon` value on **each domain controller** and correlate with logs.

### 2. Computers (`computers.csv`)

**Purpose:** Assess domain computer objects, delegation configuration, local admin password management indicators, and endpoint hygiene.

- Records computer name, DNS host name, operating system, creation time, SPNs, enabled status, and logon timestamps.
- Flags a computer as stale after **90 days** without the last observed timestamp, or `Never` when no usable value exists.
- Maps OS names to a hardcoded lifecycle table (`OSRisk`, `OSEOLDate`, `OSIsEOL`). Unknown versions cannot be accurately evaluated.
- Detects attributes associated with **legacy Microsoft LAPS** or **Windows LAPS**, along with password expiration metadata where available.
- Records unconstrained and constrained delegation, resource-based constrained delegation (RBCD) trustee SIDs, and non-DC unconstrained delegation concerns.
- Highlights constrained delegation to certain DC-related service principal names (for example, `cifs/`, `host/`, and `ldap/`).
- Distinguishes domain controllers from other computer objects using discovered DC names.

**LAPS caution:** The code requests password-bearing LAPS attributes as part of the computer query to determine whether they contain data; **it does not intentionally write those password values into `computers.csv`**. Nevertheless, plaintext LAPS values may be returned into process memory if the executing account has permission to read them. Restrict execution privileges and access to the host accordingly. An entry marked `Not Deployed` may also mean the account could not read the relevant values; verify LAPS deployment with authoritative policy and attribute checks before concluding it is absent.

### 3. Domain, controllers, trusts, and shared folders (`domain.csv`)

**Purpose:** Provide an infrastructure-level snapshot and flag risky baseline settings.

- **Domain:** DNS/NetBIOS names, distinguished name, domain/forest functional levels, and the relevant FSMO role holders.
- **Domain controllers:** Hostname, site, IP address, OS, GC/RODC status, roles, creation and last-logon context.
- **Trusts:** Inbound/outbound/bidirectional direction, trust type, selective authentication, transitivity, and SID-filtering indicators.
- **Machine Account Quota:** Reports current `ms-DS-MachineAccountQuota` and flags nonzero values for review.
- **Pre-Windows 2000 Compatible Access:** Counts members and highlights overly broad principals.
- **AdminSDHolder:** Reports suspicious powerful ACEs and the corresponding security concern.
- **SYSVOL / NETLOGON:** Reads the share paths' accessible filesystem ACLs and flags selected broad trustees with write-like permissions.

The CSV uses a **category-based format**: fields such as `Category`, `Name`, `Detail`, and `ExtraInfo` carry different meanings depending on the record category. Do not treat these as one row per DC or as normalized relational records. A trust or write-permission warning does not, by itself, prove exploitability. The SYSVOL test inspects ACLs returned by `Get-Acl` on the UNC paths and is not a complete evaluation of combined SMB share permissions, NTFS permissions, and effective access.

### 3a. Default and fine-grained password policies (`policy.csv`)

**Purpose:** Compare configured password and lockout policy with the script's built-in screening thresholds.

ForestEye reads the **default domain password policy** and each **Password Settings Object (PSO)**. It records minimum length, history, minimum/maximum age, complexity, reversible encryption, lockout threshold/duration, observation window, and applicable subjects where retrievable.

Built-in heuristic flags include:

- Minimum password length below **14** characters.
- Password history below **24** remembered passwords.
- Disabled complexity requirements.
- Zero account lockout threshold (classified as `CRITICAL` by this script) or threshold above **5**.
- Reversible password encryption enabled (`CRITICAL`).

These thresholds are **tool policy choices**, not universal security requirements. In particular, password and lockout recommendations vary by threat model, authentication architecture, and current organizational guidance. A PSO's listed subjects are not equivalent to a complete evaluation of the resultant password policy for every user.

### 4. Active Directory ACL assessment (`acl.csv`)

**Purpose:** Surface potentially dangerous ownership and permission relationships involving sensitive AD objects.

**Target discovery:** The scan intentionally emphasizes important objects rather than every object in the forest. Examples include protected users, `krbtgt`, groups, domain controllers, OUs, GPO containers, trusts, gMSAs, domain root and other well-known containers, plus relevant configuration/schema objects such as certificate-services and DNS structures when discoverable. Targets are assigned sensitivity tiers such as **P1** and **P2**.

**Trustee classification:** ACE principals are examined by SID, with special handling for broad groups (Everyone, Authenticated Users, Domain Users, and others), administrative identities, foreign principals, and unresolved/orphaned SIDs. ACL access rules are requested using SID identities to reduce repeated account-name lookups; a memoized `NTAccount`-to-SID translation fallback supports callers supplying name-based identities.

**Rights considered:** Examples include dangerous ownership, `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, broad attribute writes, replication rights, password-reset rights, group-membership modification, SPN manipulation, delegation and RBCD-related properties, shadow credentials, GPO modification, LAPS/gMSA password attributes, and selected certificate enrollment permissions. The scanner includes inherited as well as direct permission context.

**Scoring model:**

```text
ACL score = trustee weight + permission weight + target sensitivity weight

Risk bands:
  CRITICAL : score >= 25
  HIGH     : score >= 20
  MEDIUM   : score >= 15
  LOW      : score < 15

Only findings with score >= AclScoreThreshold are retained.
Default AclScoreThreshold = 12
```

The scanner caps permission weight for orphaned SIDs and groups related findings into patterns with identifiers and counts, including direct/inherited/mixed context and affected targets. Common output fields include `Score`, `Risk`, `GroupId`, `GroupSize`, `SourcePrincipal`, `Permission`, `ObjectClass`, `Inherited`, `InheritedFrom`, `InheritanceMode`, `AffectedCount`, `DirectCount`, and `InheritedCount`.

**Critical caveat:** This is a prioritized **heuristic ACL review**, not a full effective-access engine or a complete attack-path analysis. DENY ACEs, group nesting, object context, delegation constraints, and other environmental factors may change whether a reported route is usable. Review high-severity findings manually. Raising the score threshold hides lower-scoring findings; it does not make the environment safer.

### 5. Group Policy Objects (`gpo.csv`)

**Purpose:** Inventory policy objects and identify weak ownership, unusual link state, and selected policy-file security settings.

ForestEye enumerates GPOs through `Get-GPO -All`, maps links from AD `gpLink` attributes, records the owner, GPO status, dates, WMI filter, SYSVOL path, link count, and linked containers.

It also reports:

- **Unlinked GPOs:** `OrphanRisk` marks unlinked policies, with higher concern when their names imply security or hardening. An unlinked GPO is not inherently malicious.
- **Ownership:** `OwnerRisk` flags owners outside the script's recognized administrative identities.
- **GPO content:** Reads selected Registry Preferences XML, `Scripts.ini`, and `GptTmpl.inf` files in SYSVOL and searches for patterns consistent with WDigest credential exposure, Defender being disabled, AutoRun exposure, or UNC-based script references.
- **Overall content risk:** Consolidates supported pattern matches into `GpoContentRisk`.

**Scope limitation:** File patterns can have legitimate explanations and might not represent effective policy. Detection does not cover every GPO setting, every file, or every policy-processing condition. A failed SYSVOL read may reduce coverage without creating a complete GPO finding.

### 6. Local advanced audit policy (`auditpolicy.csv`)

**Purpose:** Show which advanced Windows audit subcategories are enabled on the **executing domain controller**.

When run with an elevated local administrator token, ForestEye executes:

```powershell
auditpol /get /category:* /r
```

The CSV includes `Subcategory`, `Setting`, `IsCritical`, and `Risk`. The parser uses subcategory GUIDs where possible and English names as fallback, with handling for some English/Italian audit-setting strings. Critical subcategories with no auditing are labeled `CRITICAL`; selected success-only settings are marked `Partial`.

**Scope limitation:** This is **not** a domain-wide survey of all DCs' applied audit policies. It captures the local system on which the script is run. If PowerShell is not elevated, `auditpol` fails, or rows cannot be parsed, **`auditpolicy.csv` will not be generated**. Verify actual event generation, forwarding, retention, and SIEM ingestion separately.

### 7. Additional incident-response signals (console warnings)

**Purpose:** Surface a few high-impact checks that supplement the structured reports.

- **RODC password replication policy:** Looks for selected privileged-group identities in RODC allowed password replication entries and warns about dangerous allowances.
- **AdminSDHolder:** Repeats important suspicious-ACE findings from the initial audit for immediate visibility.
- **DCShadow-style rights correlation:** Attempts to correlate relevant replication and configuration/container permissions among ACL findings.

These signals are mainly **console messages**, not a separate `ir.csv` export. The DCShadow correlation as currently written references an `AttackPath` property that is not present in the ACL output objects, so **do not rely on this check as a functioning comprehensive detector** without code review and correction. Likewise, absence of an IR warning is not evidence of absence of compromise.

### 8. Console summary

**Purpose:** Give operators a quick snapshot immediately after collection.

The summary counts domain administrators, SPN-bearing users, accounts without preauthentication, weak Kerberos settings, SID history indicators, reversible encryption, password hygiene concerns, DCSync indicators, disabled users, stale computers, LAPS gaps, EOL systems, delegation configurations, ACL severity totals, distinct ACL patterns, GPO count, and other posture indicators.

These are **counts of records matching script conditions**, not a compliance score, a confirmed incident count, or a substitute for evaluating individual findings. If `-SkipUsers`, `-SkipComputers`, or `-SkipACL` is used without valid existing CSVs, corresponding counts may misleadingly appear as zero.

### 9. Automatic HTML dashboard generation

**Purpose:** Make the audit portable and viewable without a database or web server.

The script looks for **`ForestEye.html`** in this order:

1. Same directory as `ForestEye.ps1`.
2. Parent directory of the script.
3. Current working directory.

The template must contain these exact marker comments in the expected order:

```javascript
// %%AUTO_DATA_START%%
// %%AUTO_DATA_END%%
```

ForestEye replaces the contents between them with a JavaScript `_AUTO_DATA` object holding CSV text under the keys `users`, `computers`, `domain`, `acl`, `gpo`, `policy`, and, if present, `auditpolicy`. It also adds an `injectedAt` timestamp and changes `var DASH_AUTO_LAUNCH = false` to `true` when that exact text is found.

The output file is written as **`ForestEye.html`** inside the output directory. The tool embeds CSV **strings** (not arrays of pre-parsed data objects), so the template's JavaScript must know how to parse and display those strings. Without the file, markers, or compatible JavaScript, auto-injection cannot provide a usable dashboard.

**Security:** The resulting HTML contains embedded directory inventory and findings. Treat it as sensitive even though it is a static, local file. Avoid hosting it on a publicly accessible server or forwarding it through unapproved channels. Review any template's JavaScript before use.

### 10. ZIP packaging and cleanup

**Purpose:** Consolidate everything generated in a single portable archive.

After reporting, ForestEye calls `Compress-Archive` with optimal compression and writes:

```text
<OutputPath>.zip
```

If compression completes successfully, the script **recursively deletes the uncompressed output directory**. If ZIP creation fails, it warns the user and preserves the directory. The script can replace an existing ZIP at the same location; therefore, do not reuse output paths containing irreplaceable evidence or unrelated files.

An archive may contain:

```text
ForestEye-Review.zip
├── users.csv
├── computers.csv
├── domain.csv
├── policy.csv
├── acl.csv
├── gpo.csv
├── auditpolicy.csv             # Only when successfully collected
└── ForestEye.html  # Only when successfully generated
```

CSV exports use **UTF-8 without a byte-order mark (BOM)** to improve compatibility with downstream parsers. A deliberately skipped CSV that does not already exist will not appear. Some steps may fail independently, so inspect the archive and console warnings rather than assuming every file is included.

## Reading and prioritizing findings

`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `Yes`, `No`, `Unknown`, `N/A`, and similar values are generated by different per-section rules. They are **not globally equivalent** and should not be averaged into a single score without a separately defined method. The ACL numeric score in particular uses its own 15/20/25 severity cutoffs.

A practical defensive workflow is to start with unexpected broad control of critical objects, suspicious replication rights, AdminSDHolder modifications, weak privileged-account settings, risky delegation, and insecure SYSVOL/GPO write access. Next assess password policy, audit visibility, stale identities, LAPS coverage, and unsupported operating systems. For each item, verify the source object and permissions, establish an authorized business owner, evaluate actual effective exposure, and then make any remediation changes through your normal change-management process.

## Performance, coverage, and data protection

- **Large domains:** Recursive group enumeration, the full user/computer inventory, ACL descriptor reads, and GPO SYSVOL inspection can be expensive. Run within an approved window and monitor DC health.
- **Forest versus domain:** Despite its name, ForestEye primarily builds its inventory from the **currently connected domain** and selected forest-level contexts. Do not assume it has comprehensively assessed every domain in a multi-domain forest.
- **Non-deterministic access:** LDAP and SYSVOL access failures may lead to partial results. Some errors are handled as warnings; some are silently caught.
- **Snapshots:** Reports reflect conditions observed during execution, not a transactionally consistent AD snapshot; object changes and replication delays can produce discrepancies.
- **Sensitive artifacts:** User names, SIDs, group memberships, trust configurations, security descriptors, GPO information, and embedded HTML can materially aid an adversary. Store the ZIP in a restricted location, encrypt it when transferred or archived, and apply appropriate retention/deletion controls.
- **Credentials:** The code does not explicitly export LAPS password values, password hashes, or user plaintext passwords. However, it does query certain password-bearing LAPS attributes, so tightly control process privileges and diagnostic logs/dumps.
- **No automatic fixes:** ForestEye does not change AD configurations to remediate findings. Every finding should be reviewed and corrections applied separately.

## Troubleshooting

| Symptom | Likely cause and next step |
|---|---|
| `ActiveDirectory module not found` | Install/enable the AD PowerShell tools on the authorized Windows host. |
| Cannot connect to AD | Check domain membership, DNS, DC connectivity, account permissions, and AD service health. |
| Cannot write to output directory | Choose a writable local location and verify available space and access controls. |
| `auditpolicy.csv` missing | Relaunch an elevated PowerShell session on the relevant DC, or inspect `auditpol` errors and parsing compatibility. |
| `gpo.csv` missing | Verify the GroupPolicy module, SYSVOL access, and the `Get-GPO` command. |
| Dashboard missing | Provide the correctly named HTML template with both marker comments; check the console for injection errors. |
| Dashboard opens but shows no data | Confirm the template supports `_AUTO_DATA` CSV strings and auto-launch; inspect the embedded data block. |
| Missing CSV after `-Skip*` | No matching file was present in the selected output directory for reuse. |
| Unexpectedly few ACL findings | Check permissions, scan warnings, target scope, and the chosen ACL threshold. |
| Output directory disappeared | Successful ZIP packaging deliberately removes the intermediate output folder. Extract the `.zip` file. |
| OS/LAPS status looks inaccurate | Check outdated lifecycle assumptions, forest schema, read permissions, and endpoint-specific deployment information. |
