# Methodology — Repeatable Memory Forensics Workflow

This document describes the workflow this repo automates so that another
analyst can reproduce any investigation from the same image and reach the
same evidence pack.

## 1. Principles

**Evidence is read-only.** A memory image is evidence. The pipeline computes
a SHA256 of the image *before* any analysis, runs every plugin in read-only
mode, then re-hashes and asserts the digest is unchanged. A mismatch raises
`IntegrityError` and is recorded. This is standard chain-of-custody hygiene:
if the hash chain breaks, findings derived from that image are challengeable.

**Reproducibility over cleverness.** Every command executed — including the
OS-detection probes — is appended to `run_log.txt` with a UTC timestamp. The
same image and plugin list always produce the same evidence pack. Anyone can
replay the run log line by line with stock Volatility 3 and get the same data.

**The tool collects; the analyst concludes.** Extraction heuristics (IOCs,
suspicious names) only *surface candidates*. There is deliberately no scoring
or automated verdict — conclusions live in the investigation reports, written
by a human, with the evidence cited.

## 2. Pipeline stages

```
image ──> intake ──> OS detect ──> plugin runner ──> evidence pack ──> IOC extract ──> report scaffold
          (SHA256)   (windows.info │ banners)        (JSON + txt       (iocs.json,      (Markdown,
                                                      + run_log)        defanged)        analyst TODOs)
                                          └── post-run SHA256 re-verify ──┘
```

Run with:

```bash
python -m src.cli analyze images/<image>
```

### Stage 1 — Intake (`src/intake.py`)
- Validate the path/extension; stream-hash the image (chunked SHA256, never
  loaded into RAM — images are multi-GB).
- Record Volatility version, file size, and UTC timestamp into
  `image_metadata.json`.

### Stage 2 — OS detection
- Try `windows.info` first: Windows symbol tables (PDBs) auto-download from
  Microsoft, so this is the cheap common case and yields NT version/build.
- Fall back to `banners.Banners` to spot Linux kernels. Linux analysis
  additionally requires an ISF symbol table matching the exact kernel — see
  §5.

### Stage 3 — Curated plugin set (`src/config.py`)
Plugins run in triage order; the rationale for each is kept next to the
plugin name in `config.py` and summarised in the README. Key design choices:

- **Cross-view analysis**: `pslist` (linked list the OS admits to) is always
  paired with `psscan` (pool-tag scanning). A process present in `psscan`
  but missing from `pslist` is hidden (DKOM) or recently terminated — this
  differential is computed automatically during IOC extraction.
- **Failure isolation**: each plugin runs in its own subprocess with a
  timeout. A failing plugin is logged (`plugin_results.json`) and skipped —
  one parse error never costs the rest of the evidence.
- **Dual capture**: every plugin's output is stored as JSON (`-r json`,
  machine-readable, lossless) and as an aligned text table (human-readable,
  truncated at 2000 lines).

### Stage 4 — Evidence pack (`src/evidence.py`)
One timestamped directory per run:

```
evidence/<image-stem>_<UTC>/
├── image_metadata.json    # hash, size, OS, vol version, integrity flag
├── run_log.txt            # every command, timestamped
├── plugin_results.json    # status/duration/error per plugin
├── plugins/*.json|.txt    # raw captures
├── iocs.json              # extracted candidates (ThreatLens-ready)
└── report_scaffold.md     # pre-filled report, analyst sections marked
```

### Stage 5 — IOC extraction (`src/iocs.py`)
Heuristics, each tagged with the *reason* it fired so the analyst can audit:

- external (routable, non-private) foreign IPs from `netscan`/`netstat`;
- processes with suspicious names or hidden from `pslist` (cross-view);
- command lines showing LOLBin abuse (`powershell -enc`, `rundll32`,
  `certutil -urlcache`, …) or execution from user-writable paths
  (`\Temp\`, `\AppData\`, …);
- `malfind` regions that are executable (`PAGE_EXECUTE_*`) and private —
  the classic injected-code signature.

IPs are **defanged** (`41.168.5[.]140`) in all human-readable output and kept
raw in `iocs.json` for machine hand-off (optionally POSTed to ThreatLens when
`THREATLENS_BASE_URL` is configured; skipped cleanly offline).

### Stage 6 — Report scaffold (`src/report.py`)
Generates `report_scaffold.md` with the case-summary table, methodology
(plugin run table), and the key evidence tables (processes, external
connections, malfind hits, IOCs) pre-filled. Every judgement section is
marked `[ANALYST]`. Final reports are copied to `docs/investigations/` and
completed by hand.

## 3. Analysis approach (the human part)

The triage order encoded in the plugin list is also the reading order:

1. `windows.info` — does the image parse, what OS am I looking at?
2. `pslist`/`psscan`/`pstree` — what ran? Compare views; check parentage
   (e.g. `cmd.exe` spawned by `winword.exe` is a finding).
3. `cmdline` — *how* was it launched? Often the smoking gun.
4. `netscan` — who was it talking to? External IPs become IOCs.
5. `malfind` — injected code in otherwise legitimate processes.
6. `dlllist`/`svcscan`/registry — persistence and module anomalies.
7. If a process is condemned by the above: dump it (`windows.dumpfiles`
   on demand), hash it, check against threat intel.

Findings are then mapped to MITRE ATT&CK techniques and assembled into the
timeline → verdict → recommendations structure used by every report in
`docs/investigations/`.

## 4. Verification of this pipeline

- `tests/test_iocs.py` covers the extraction heuristics with fixtures that
  mirror real Volatility output (10 tests).
- The full pipeline (intake → 12 plugins → integrity check → IOCs → report)
  is smoke-tested end-to-end with a stub `vol` emitting realistic JSON, so
  pipeline mechanics are verified independently of any particular image.

## 5. Known limitations

- **Linux/macOS images** need an ISF symbol table matching the exact kernel
  (`dwarf2json`); the Linux plugin set is wired up but untested — documented
  stretch goal.
- **First Windows run needs network** for symbol download from Microsoft
  (cached afterwards under `symbols/`; subsequent runs are offline).
- IOC heuristics are triage aids, not detection engineering — false
  positives are expected and acceptable; the analyst dispositions them.
