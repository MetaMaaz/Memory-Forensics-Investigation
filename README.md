# Memory Forensics Investigation

**A repeatable DFIR workflow: memory image in → structured, integrity-verified evidence pack out — built on Volatility 3, finished by a human analyst.**

This is a digital-forensics portfolio project demonstrating the *investigate*
stage of incident response: triaging captured RAM for malicious processes,
injected code, C2 traffic and persistence, then writing the findings up the
way a SOC/DFIR team would — evidence-led, MITRE-mapped, with a verdict and
recommendations.

📄 **The investigations are the headline deliverable → [`docs/investigations/`](docs/investigations/)**

## Why memory forensics

Disk forensics shows what was installed; memory shows what was *running*.
Fileless malware, reflectively loaded implants (Meterpreter), injected code
and live C2 sessions often exist **only** in RAM. Being able to take a
memory image and answer "was this host compromised, by what, talking to
whom?" is a core DFIR skill — this repo turns that into a repeatable,
auditable workflow.

## How it works

```
image ──> intake ──> OS detect ──> plugin runner ──> evidence pack ──> IOC extract ──> report scaffold
          (SHA256)   (windows.info)  (12 curated       (JSON + txt        (iocs.json,     (Markdown,
                                      Vol3 plugins)     + run_log.txt)     defanged)       analyst TODOs)
                                          └──── post-run SHA256 re-verification ────┘
```

The tool collects and organises; **it never auto-concludes**. Verdicts,
timelines and ATT&CK mappings are written by the analyst in the report —
that separation is by design.

## Install & usage

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
vol --help                               # verify Volatility 3 (2.28.0+)

# full pipeline: hash -> detect OS -> plugins -> evidence pack -> IOCs -> report
python3 -m src.cli analyze images/<image>

# re-run pieces against an existing evidence pack
python3 -m src.cli iocs   evidence/<pack>
python3 -m src.cli report evidence/<pack> --case-name "Case 03"

pytest                                    # 10 tests on the IOC heuristics
```

Each run creates `evidence/<image>_<UTC>/` containing `image_metadata.json`
(incl. SHA256 + integrity flag), `run_log.txt` (every command executed),
per-plugin JSON + text output, `iocs.json`, and `report_scaffold.md`.

## The curated plugin set (and why)

| Plugin | Why it matters |
|--------|----------------|
| `windows.info` | Confirms the image parses; OS/build for the case file |
| `windows.pslist` | Processes the OS admits to |
| `windows.psscan` | Pool-scanned processes — the **cross-view diff vs pslist exposes hidden/terminated procs (DKOM)**, computed automatically |
| `windows.pstree` | Parentage — `cmd.exe` under `winword.exe` is a finding |
| `windows.cmdline` | How things launched; often the smoking gun |
| `windows.netscan` / `netstat` | External connections → C2 IOCs |
| `windows.dlllist` | Odd-path / unsigned modules |
| `windows.malfind` | RWX private memory with no file backing — injected code |
| `windows.svcscan` | Service-based persistence |
| `windows.registry.hivelist` | Pivot point for run-key persistence |
| `windows.handles` | What a condemned process was touching |

The list lives in [`src/config.py`](src/config.py) — adding a plugin is one
line. A Linux set (`linux.pslist`, `linux.bash`, `linux.check_syscall`, …)
is wired up as a stretch goal (requires ISF symbols).

## Evidence integrity (chain of custody)

Every image is SHA256-hashed **before** analysis and re-hashed **after**;
the run aborts with `IntegrityError` on mismatch and the verified flag is
recorded in the evidence pack. Combined with the timestamped `run_log.txt`
of every command executed, any investigation here can be independently
replayed and checked — the difference between "trust me" and evidence.

## Investigations

| Case | Scenario | Key techniques |
|------|----------|----------------|
| [01 — Cridex banking trojan](docs/investigations/case-01-cridex-banking-trojan.md) | Commodity malware on XP: masquerading, injection into explorer.exe, run-key persistence, HTTP C2 | T1036.005, T1055, T1547.001, T1071.001 |
| [02 — DumpMe Meterpreter intrusion](docs/investigations/case-02-dumpme-meterpreter-intrusion.md) | Interactive attacker on Win7: random-named payload, reflective loading, internal C2 on :4444, data access | T1204.002, T1620, T1571, T1005 |
| [03 — HFS exploitation / RAT deployment](docs/investigations/case-03-hfs-exploitation-triage.md) | CVE-2014-6287 → VBS dropper → UWkpjFjDzM.exe → injection into 14 processes; SMTP exfil candidates | T1190, T1059.005, T1055, T1036, T1114, T1048.003 |
| [04 — Reveal / StrelaStealer credential theft](docs/investigations/case-04-reveal-strelastealer.md) | StrelaStealer on Win10: phishing → hidden PowerShell → WebDAV `net use` → `rundll32` of remote DLL (no-disk); Thunderbird credential theft | T1566.001, T1059.001, T1218.011, T1620, T1571, T1555, T1114 |

See [`docs/investigations/README.md`](docs/investigations/README.md) for
report status and the validation workflow, and
[`docs/methodology.md`](docs/methodology.md) for the full reproducible
methodology.

## IOC extraction & ThreatLens hand-off

`src/iocs.py` surfaces *candidates* with an auditable reason per hit:
external IPs (auto-defanged: `41.168.5[.]140`), hidden-process cross-view
diffs, LOLBin command lines (`powershell -enc`, `certutil -urlcache`, …),
user-writable execution paths, and executable malfind regions.

`iocs.json` is shaped for hand-off to **[ThreatLens](https://github.com/maazhusain)** —
my IOC-enrichment platform — via `--threatlens` (URL/key in `.env`, see
`.env.example`). Fully optional: the pipeline runs offline and skips
enrichment cleanly when unconfigured.

## Getting memory images (legal + safe)

Images are **gitignored** (multi-GB, and some contain live malware — this
repo does static analysis only; never extract-and-run artefacts). Lawful
public sources, documented per-case in each report:

- **CyberDefenders** blue-team labs (DumpMe, Reveal, Ramnit) — modern, scenario-driven
- **Volatility Foundation samples wiki** — classic images (Cridex, Zeus, R2D2)
- **13Cubed** memory-forensics challenges

Windows symbol tables auto-download from Microsoft on first run (cached in
`symbols/` afterwards).

## Tech stack & what I learned

Python 3.11 · Volatility 3 · Typer · Jinja2 · pytest — ~700 lines of
orchestration, deliberately readable over clever.

Building this taught me: why cross-view detection (`pslist` vs `psscan`)
beats trusting any single OS structure, how `malfind` separates injected PE
images from benign JIT memory, why chain-of-custody hashing has to wrap the
*entire* run, and how to write findings so that another analyst — or a
courtroom — can retrace every step from the run log.

## Repo map

```
src/            pipeline (intake → runner → evidence → iocs → report → cli)
tests/          IOC-heuristic tests (fixtures mirror real Volatility output)
docs/methodology.md            the reproducible workflow
docs/investigations/           ★ the case reports
images/ evidence/              gitignored working dirs
```
