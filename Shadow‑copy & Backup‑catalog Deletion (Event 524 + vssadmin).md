# Shadow‑Copy & Backup‑Catalog Deletion Detection

## Key Concepts

* **Volume Shadow Copy Service (VSS)** – Windows feature that stores point‑in‑time snapshots of files and volumes so they can be restored after corruption or ransomware.
* **`vssadmin delete shadows`** – Command‑line that erases all shadow copies; widely abused by ransomware prior to encryption.
* **Backup Catalog (Event ID 524)** – Logged by *Microsoft‑Windows‑Backup* when the Windows backup catalog is deleted (e.g., `wbadmin delete catalog`); prevents full‑system restores.
* **Impact** – Destroying both shadow copies and the backup catalog removes native recovery options, forcing victims to pay or rebuild.

---

## The query

```kql
let LookbackHours = 6h;
let JoinWindow    = 10m;
let VssAdminDeletes =
    SecurityEvent
    | where TimeGenerated > ago(LookbackHours)
    | where EventID == 4688
    | where CommandLine has_cs "vssadmin"
          and CommandLine has_cs "delete"
          and CommandLine has_cs "shadows"
    | project Computer,
              vssTime = TimeGenerated,
              Account,
              CommandLine;
let BackupCatalogDeleted =
    Event
    | where TimeGenerated > ago(LookbackHours)
    | where EventID == 524
          and Source =~ "Microsoft-Windows-Backup"
    | project Computer,
              catTime = TimeGenerated,
              BackupEventMsg = RenderedDescription;
VssAdminDeletes
| join kind=inner (BackupCatalogDeleted) on Computer
| where catTime between (vssTime - JoinWindow .. vssTime + JoinWindow)
| extend TimeDelta = datetime_diff("second", catTime, vssTime)
| project Timestamp = vssTime,
          Computer,
          Account,
          CommandLine,
          BackupEventMsg,
          TimeDelta
```

---

### What the query does

1. **Captures shadow‑copy deletions** – Looks for process‑creation Event 4688 where `vssadmin.exe` deletes shadows.
2. **Captures backup‑catalog deletions** – Filters Application‑log Event 524 from *Microsoft‑Windows‑Backup*.
3. **Correlates both events** on the same host within ±10 minutes.

   * Legitimate maintenance rarely performs these two destructive actions in close succession.
4. **Outputs** timestamp, host, user account, exact command line, backup‑event text, and the second‑level delta between them.

---

## MITRE ATT\&CK Mapping

| Tactic     | Technique               | ID        |
| ---------- | ----------------------- | --------- |
| **Impact** | Inhibit System Recovery | **T1490** |

---

## Usage Tips

* **Tune exclusions** – Exclude backup software service accounts or maintenance windows.
* **Enable Event 4688** – Ensure process‑creation auditing is on and forwarded to **SecurityEvent**.
* **Automate response** – Tie the rule to a playbook that isolates the host, collects a forensic image, and triggers backup‑integrity checks.

---

## Useful Links

* [Microsoft Docs – *vssadmin* commands](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin)
* [Microsoft Docs – *wbadmin delete catalog*](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin-delete-catalog)
* [MITRE ATT\&CK T1490](https://attack.mitre.org/techniques/T1490/)
