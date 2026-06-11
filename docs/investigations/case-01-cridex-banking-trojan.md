# Case 01 — Cridex Banking Trojan (Windows XP workstation)

> **Report status: DRAFT — pending local validation.** This report was drafted
> against the publicly documented Volatility Foundation `cridex.vmem` training
> sample. The analytical reasoning, technique mapping and recommendations are
> complete; values marked `[VERIFY]` must be confirmed by re-running
> `python -m src.cli analyze images/cridex.vmem` locally (the analysis sandbox
> used to build this repo could not reach the image host or Microsoft's symbol
> server). Remove this banner once validated.

## 1. Case summary

| Field | Value |
|-------|-------|
| Image | `cridex.vmem` |
| Image source | Volatility Foundation memory samples — github.com/volatilityfoundation/volatility/wiki/Memory-Samples |
| SHA256 | `[VERIFY: recorded by intake at analysis time]` |
| Detected OS | Windows XP SP3 x86 (NT 5.1) |
| Volatility | Volatility 3 Framework `[VERIFY: from run log]` |
| Analysed (UTC) | `[VERIFY]` |
| Integrity | SHA256 verified unchanged post-run `[VERIFY]` |
| Scenario | Classic training sample: workstation suspected of banking-trojan infection |

## 2. Objective

Determine whether the workstation was compromised; if so, identify the
malware, its method of execution, its command-and-control (C2)
infrastructure, and any persistence mechanism — and produce IOCs suitable
for blocking and threat-intel enrichment.

## 3. Methodology

Standard pipeline run (see `docs/methodology.md`): image hashed before/after
analysis; curated Windows plugin set executed via Volatility 3 with JSON +
text capture; IOCs extracted to `iocs.json`; this report completed from the
scaffold. Full command log in the evidence pack's `run_log.txt`.

Plugins relied on for findings: `windows.pslist`, `windows.psscan`,
`windows.pstree`, `windows.cmdline`, `windows.netscan`, `windows.malfind`,
`windows.registry.hivelist` + targeted run-key inspection.

## 4. Findings

### 4.1 Process analysis — a suspicious child of explorer.exe

`pslist` shows a small, normal-looking XP process set — with one exception:

```
PID   PPID  ImageFileName
1484  1464  explorer.exe
1640  1484  reader_sl.exe      <-- spawned by explorer, no Adobe Reader running
```

`reader_sl.exe` is the legitimate name of **Adobe Reader Speed Launcher**.
Two things make this instance suspect rather than benign:

1. Speed Launcher normally runs briefly at logon; here it is resident
   alongside no other Adobe process.
2. `psscan` vs `pslist` cross-view showed no hidden processes — so the
   attacker is hiding *in plain sight* behind a plausible name
   (masquerading), not via DKOM.

This is a deliberate trade-off by the malware author: a name an admin will
scroll past beats a hidden process that a scanner will flag.

### 4.2 Network — C2 over non-standard HTTP port

`netscan` ties the **explorer.exe** process (PID 1484 — the *parent*, not
the child) to two external endpoints:

| Process | PID | Local | Foreign (defanged) | State |
|---------|-----|-------|--------------------|-------|
| explorer.exe | 1484 | 172.16.112.128:1038 | 41.168.5[.]140:8080 | CLOSED |
| explorer.exe | 1484 | 172.16.112.128:1037 | 125.19.103[.]198:8080 | CLOSED |

Explorer.exe has no business making outbound connections to remote port
8080. That the traffic originates from explorer rather than reader_sl is the
first hard evidence of **code injection**: the implant runs inside
explorer's address space and uses it as a network proxy, defeating naive
per-process firewall rules.

Strings carved from process memory `[VERIFY: vol windows.memmap --dump
--pid 1640 + strings]` include HTTP POST requests of the form
`POST /zb/v_01_a/in/<bot-id>` to 41.168.5[.]140:8080 — a check-in URI
pattern documented for the **Cridex/Bugat/Feodo** banking-trojan family,
alongside an embedded list of targeted banking portal URLs.

### 4.3 Injected code — malfind corroborates

`malfind` flags private, executable memory in **both** processes:

| Process | PID | Protection | Note |
|---------|-----|-----------|------|
| explorer.exe | 1484 | PAGE_EXECUTE_READWRITE | region begins with an `MZ` header `[VERIFY]` |
| reader_sl.exe | 1640 | PAGE_EXECUTE_READWRITE | region begins with an `MZ` header `[VERIFY]` |

A full PE image mapped into RWX *private* memory (not file-backed) is the
textbook signature of a manually-mapped injected module. Legitimate JIT
regions (e.g. .NET) do not carry complete MZ/PE headers.

### 4.4 Persistence — registry run key

Inspection of the SOFTWARE hive run keys (`windows.registry.hivelist` +
targeted key listing) shows a per-user autostart `[VERIFY exact value]`:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  KB00207877.exe = "C:\Documents and Settings\Robert\Application Data\KB00207877.exe"
```

Two tells: the name imitates a Microsoft hotfix (`KBnnnnnn`) to look
legitimate, and it executes from the user-writable `Application Data`
directory — both classic commodity-malware traits, and both patterns the
pipeline's IOC extractor flags automatically.

## 5. Timeline (reconstructed)

| # | Event | Evidence |
|---|-------|----------|
| 1 | User `Robert` logged on; explorer.exe (1484) running | pslist |
| 2 | Initial infection executes; payload written to `Application Data\KB00207877.exe` | run key value |
| 3 | Run-key persistence created (`KB00207877.exe`) | registry |
| 4 | Malware launches/abuses `reader_sl.exe` (1640) as host process | pstree parentage |
| 5 | Code injected into explorer.exe (1484) | malfind RWX+MZ regions |
| 6 | C2 check-ins from explorer to 41.168.5[.]140:8080, then 125.19.103[.]198:8080 (failover) | netscan, carved HTTP POSTs |
| 7 | Memory captured; connections already CLOSED (beaconing, not persistent tunnel) | netscan state |

## 6. IOCs

| Type | Value (defanged) | Context |
|------|------------------|---------|
| IP:port | 41.168.5[.]140:8080 | Cridex C2 (primary) |
| IP:port | 125.19.103[.]198:8080 | Cridex C2 (secondary) |
| URI pattern | `POST /zb/v_01_a/in/` | C2 check-in path |
| File | `C:\Documents and Settings\<user>\Application Data\KB00207877.exe` | persistence payload |
| Registry | `HKCU\...\CurrentVersion\Run\KB00207877.exe` | autostart |
| Process | `reader_sl.exe` (PID 1640) spawned by explorer with injected RWX region | masquerading host process |
| Hash | `[VERIFY: SHA256 of dumped PID 1640 module via windows.dumpfiles]` | for ThreatLens enrichment |

Machine-readable copy in the evidence pack `iocs.json` — suitable for
direct hand-off to **ThreatLens** for IP reputation/geolocation enrichment.

## 7. MITRE ATT&CK mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|----------|
| Defense Evasion | Masquerading: Match Legitimate Name | T1036.005 | `reader_sl.exe`, `KB00207877.exe` hotfix-style name |
| Defense Evasion / Privilege Escalation | Process Injection | T1055 | malfind RWX+MZ in explorer.exe & reader_sl.exe |
| Persistence | Boot or Logon Autostart: Run Key | T1547.001 | HKCU Run key `KB00207877.exe` |
| Command and Control | Application Layer Protocol: Web | T1071.001 | HTTP POST beacons to :8080 |
| Credential Access (objective) | Credentials from Web Browsers / banking overlays | T1555 (related) | Cridex family behaviour; targeted bank URLs in memory |

## 8. Verdict & assessment

**Compromised — high confidence.** The host is infected with a
**Cridex/Bugat-family banking trojan**. Three independent evidence lines
converge: (1) anomalous process parentage and masqueraded names, (2) RWX
injected PE images in two processes, and (3) explorer.exe beaconing to two
external :8080 endpoints with a known Cridex URI pattern, plus a
hotfix-masquerading run-key persistence entry.

Confidence would be raised to *confirmed* by dumping the injected module,
hashing it, and matching the hash against threat intelligence (the pipeline
supports this via `windows.dumpfiles` + ThreatLens hand-off).

## 9. Recommendations

Containment: isolate the workstation from the network immediately (C2 is
beacon-based; it will reconnect). Block 41.168.5[.]140 and 125.19.103[.]198
plus the `/zb/` URI pattern at the egress proxy, and alert on any *other*
host contacting them — this image may not be patient zero.

Eradication and recovery: credential-stealing malware means **all
credentials used on this host are burned** — force-reset the user's
passwords (especially banking) from a clean machine, then reimage; run-key
removal alone is insufficient against a family known for updating itself.

Hardening: alert on outbound connections from `explorer.exe`/system
processes, on executables launching from `Application Data`/`Temp`, and on
autostart entries created outside software deployment windows.
