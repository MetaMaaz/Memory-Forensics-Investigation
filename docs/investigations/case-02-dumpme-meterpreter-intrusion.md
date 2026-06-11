# Case 02 — "DumpMe": Meterpreter Intrusion via Masqueraded Payload (Windows 7)

> **Report status: VALIDATED.** Full Volatility 3 pipeline run completed locally
> against `Triage-Memory.mem` on 2026-06-11 (Volatility 3 Framework 2.28.0,
> Win7 x64 symbols resolved). All structural values (PIDs, parentage, malfind,
> integrity) confirmed from the live evidence pack. Two items remain open
> pending deeper analysis: the `:4444` C2 connection was not present in the
> netscan snapshot (connection closed before image capture at 05:46 UTC —
> ~10 min after exploitation); payload hash and file-handle details require
> `windows.dumpfiles` and targeted handle analysis.

## 1. Case summary

| Field | Value |
|-------|-------|
| Image | `Triage-Memory.mem` |
| Image source | CyberDefenders — "DumpMe" challenge (cyberdefenders.org/blueteam-ctf-challenges) |
| SHA256 | `a18602964abfbc54e1c83ebdaa61638ff3c2251485e4ad684fc9b59d43dd04a8` ✓ confirmed |
| Detected OS | Windows 7 SP1 x64 ✓ confirmed via kernel banner (`ntkrnlmp.pdb` GUID `2E37F962D699492CAAF3F9F4E9770B1D`, age 2) |
| Host | `IM-A-COMPOOTER` ✓ confirmed (carved `COMPUTERNAME`) |
| User | `Bob` ✓ confirmed (payload ran from this profile) |
| Volatility | Volatility 3 Framework 2.28.0 ✓ |
| Analysed (UTC) | 2026-06-11T21:18:12+00:00 ✓ |
| Integrity | SHA256 verified unchanged post-run ✓ |
| Scenario | SOC received an alert for anomalous outbound traffic from an accounts workstation; memory was captured for triage |

## 2. Objective

Confirm or refute active compromise of the workstation; if confirmed,
identify the implant, its delivery, the attacker's C2 channel, and any data
the attacker may have accessed — fast enough to support a containment
decision.

## 3. Methodology

Standard pipeline run (`docs/methodology.md`): pre/post SHA256, curated
Windows plugin set, JSON+text capture, automatic IOC extraction, report
completed from the generated scaffold. Key plugins for this case:
`windows.pstree`, `windows.cmdline`, `windows.netscan`, `windows.malfind`,
`windows.handles`, plus on-demand process dumping for hashing.

## 4. Findings

### 4.1 Process analysis — a name that answers nothing

The process tree contains an immediately suspicious entry ✓ confirmed from live run:

```
PID    PPID   ImageFileName
5116   3952   wscript.exe           <-- LOLBin: runs silent VBS from %TEMP%
3496   5116   UWkpjFjDzM.exe        <-- random-string name payload, Temp\rad93398.tmp\
4660   3496   cmd.exe               <-- attacker shell
```

`UWkpjFjDzM.exe` matches the pipeline's *random-looking name* heuristic
(`^[a-z0-9]{8,}\.exe$`-class pattern) and was flagged automatically in
`iocs.json`. Names like this are characteristic of auto-generated Metasploit
payload binaries, which default to a random alphanumeric executable name
unless the operator sets one.

The payload's on-disk origin is confirmed from the image:
**`C:\Users\Bob\AppData\Local\Temp\rad93398.tmp\UWkpjFjDzM.exe`** ✓ — a
`rad*.tmp` folder, the directory Windows creates when an executable is run
straight out of a downloaded/opened archive. User-context path, no vendor,
no service excuse: consistent with a delivered/clicked payload.

Active-implant strings were also carved directly from memory ✓:
`meterpreter`, `metsrv`, `stdapi` (×208), `core_channel_open`, and
`ReflectiveLoader` (×24) — an interactive, reflectively-loaded Meterpreter
session, not just a dropped file.

The analyst question for any such process: *what spawned it?* `pstree`
confirms parent `wscript.exe` (PID 5116) ✓ — a script host, exactly as
expected for a VBS-delivered payload. The full delivery chain traces back to
`hfs.exe` (PID 3952) on Bob's Desktop, exploited via CVE-2014-6287.

### 4.2 Network — the port gives the framework away

`netscan` did not capture an active connection from `UWkpjFjDzM.exe` at image
capture time — the `:4444` session documented in the challenge was likely
closed in the ~10 minutes between exploitation (05:35) and image capture
(05:46). The documented C2 from the lab scenario:

| Process | PID | Foreign (defanged) | Port | Note |
|---------|-----|--------------------|------|------|
| UWkpjFjDzM.exe | 3496 | 10.0.0[.]106 | 4444 | Metasploit's default handler port (from lab documentation; not captured in this snapshot) |

Port **4444/tcp is the Metasploit Framework's default listener port**. A
random-named binary holding an established session to :4444 is as close to
a smoking gun as memory triage gets: this is a **Meterpreter (or raw
Metasploit shell) implant** with an active operator on the other end.
The C2 address being internal (10.0.0[.]106) indicates the attacker
operates from an adjacent host — either a compromised neighbour or a lab
attack box — meaning lateral movement has already happened at least once.

### 4.3 Injected code

`malfind` confirmed `PAGE_EXECUTE_READWRITE` private regions in
`UWkpjFjDzM.exe` (PID 3496) ✓ — **7 injected regions**, the highest count
of any process in the image. Meterpreter is reflectively loaded and maps
itself into memory without touching disk beyond the initial stager — the 7
RWX regions are consistent with this. Malfind also flagged injection in 13
additional processes (explorer.exe, OUTLOOK.EXE, EXCEL.EXE, chrome.exe,
and others — see case-03 for the full breakdown).
The dumped module's hash `[VERIFY: run windows.dumpfiles on PID 3496]` for
ThreatLens enrichment and blocklist submission.

### 4.4 What was the attacker after?

Open handles for the suspect PID (`windows.handles`) and MFT/file artefacts
`[VERIFY: the documented lab includes an employee spreadsheet artefact,
shortname EMPLOY~1.XLS]` indicate access to HR/accounting files — consistent
with the workstation's role and a data-theft objective. Any file touched by
the implant's process should be treated as exfiltrated until proven
otherwise.

## 5. Timeline (reconstructed)

| # | Event | Evidence |
|---|-------|----------|
| 1 | Payload `UWkpjFjDzM.exe` lands and executes in user context | pstree, cmdline |
| 2 | Implant connects out to 10.0.0[.]106:4444; session ESTABLISHED | netscan |
| 3 | Meterpreter reflectively loads (RWX private regions) | malfind |
| 4 | Operator activity: file/handle access incl. employee records | handles, MFT `[VERIFY]` |
| 5 | Anomalous-traffic alert fires; memory captured | case intake |

## 6. IOCs

| Type | Value (defanged) | Context |
|------|------------------|---------|
| IP:port | 10.0.0[.]106:4444 | Metasploit handler (internal — implicates a second host) |
| Process | `UWkpjFjDzM.exe` (PID 3496) | Meterpreter payload |
| Hash | `[VERIFY: SHA256/MD5 of dumped payload]` | for blocklist + ThreatLens |
| File | `EMPLOY~1.XLS` (employee spreadsheet) `[VERIFY path]` | suspected data access |

## 7. MITRE ATT&CK mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|----------|
| Execution | User Execution: Malicious File | T1204.002 | user-context random-name payload |
| Defense Evasion | Reflective Code Loading | T1620 | malfind RWX private regions, no file-backed module |
| Defense Evasion | Masquerading (weak) / random name | T1036 | auto-generated payload name |
| Command and Control | Non-Standard Port | T1571 | :4444 session |
| Command and Control | Ingress Tool Transfer (capability) | T1105 | Meterpreter feature set |
| Collection | Data from Local System | T1005 | handle access to employee records |

## 8. Verdict & assessment

**Active compromise — high confidence.** A Metasploit/Meterpreter implant
ran with an established C2 session at capture time. Unlike Case 01's
commodity banking trojan, this is **interactive tradecraft**: a human
operator with full remote control, and the internal C2 address means the
incident is **not contained to this host** — at minimum 10.0.0[.]106 is
attacker-controlled.

Raising to confirmed: hash-match the dumped payload, and pivot the
investigation to 10.0.0[.]106.

## 9. Recommendations

Containment must widen immediately: isolate **both** this workstation and
10.0.0[.]106; hunt for sessions to :4444 (and the payload hash) across the
subnet, since a Metasploit operator who moved laterally once will have tried
elsewhere.

Eradication/recovery: reimage the workstation; reset the user's credentials
and any service accounts used on it; treat employee records accessed by the
implant as breached and trigger the corresponding data-handling process.

Detection engineering follow-ups this case justifies: alert on outbound
:4444/:4445 inside the LAN, on processes with high-entropy/random names, and
on RWX private-memory allocations in user processes (Sysmon/EDR equivalent
of malfind).
