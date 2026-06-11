# Investigations

Completed case reports produced with this repo's pipeline. Each follows the
nine-section format defined in the project spec: case summary → objective →
methodology → findings → timeline → IOCs → MITRE ATT&CK → verdict →
recommendations.

| Case | Scenario | Status |
|------|----------|--------|
| [01 — Cridex banking trojan](case-01-cridex-banking-trojan.md) | Commodity malware: injection, run-key persistence, HTTP C2 | Draft — pending local validation |
| [02 — DumpMe Meterpreter intrusion](case-02-dumpme-meterpreter-intrusion.md) | Interactive attacker: Metasploit payload, internal C2, data access | **Validated** — live run 2026-06-11 |
| [03 — HFS exploitation / RAT deployment](case-03-hfs-exploitation-triage.md) | CVE-2014-6287 → VBS dropper → payload → injection into 14 processes; SMTP exfil candidates | **Complete** — live run 2026-06-11 |
| 04 — Credential-theft scenario (planned) | A lab with lsass access / hashdump activity (e.g. CyberDefenders "Reveal" or 13Cubed Mini Memory CTF) to cover T1003 | Planned |

## Why "draft — pending local validation"?

These reports were written against **publicly documented training scenarios**
(Volatility Foundation samples wiki; CyberDefenders labs). The environment in
which this repo was built could not download the multi-GB images or reach
Microsoft's symbol server, so concrete values that must come from a live run
(image hashes, exact PIDs/timestamps, dumped-module hashes) are marked
`[VERIFY]`.

To validate a report:

1. Download the image (sources in each report's case summary) into `images/`.
2. `python3 -m src.cli analyze images/<image>`
3. Diff the report's tables against the generated evidence pack, fill every
   `[VERIFY]`, and remove the draft banner.

This is deliberate chain-of-custody honesty: a forensic report never states
values that weren't observed from the evidence at hand.
