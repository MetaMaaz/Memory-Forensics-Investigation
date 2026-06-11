"""FR5 — Investigation report scaffolding.

Generates a Markdown report pre-filled with the evidence pack's key tables
(processes, network, malfind hits, IOCs) following SPEC §6. Analysis sections
are left as clearly marked TODOs — the tool fills data, the analyst fills
judgement.
"""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Template

from .evidence import load_plugin_json
from .iocs import defang_ip, is_external_ip

TEMPLATE = Template("""\
# Investigation Report — {{ case_name }}

> **Status:** SCAFFOLD — sections marked `[ANALYST]` require human analysis.

## 1. Case summary

| Field | Value |
|-------|-------|
| Image | `{{ meta.filename }}` |
| Image source | [ANALYST: where the image came from + URL] |
| SHA256 | `{{ meta.sha256 }}` |
| Size | {{ "%.1f"|format(meta.size_bytes / 1048576) }} MB |
| Detected OS | {{ os_summary }} |
| Volatility | {{ meta.volatility_version }} |
| Analysed (UTC) | {{ meta.analysed_at_utc }} |
| Integrity verified post-run | {{ "yes" if meta.sha256_verified_after_run else "NO — investigate" }} |

## 2. Objective

[ANALYST: what question does this investigation answer? e.g. "Determine whether
the host was compromised, identify the malware, its C2, and persistence."]

## 3. Methodology

Automated triage via this repo's pipeline (`python -m src.cli analyze`):
image hashed (SHA256) before and after analysis; the curated Volatility 3
plugin set below was executed and captured as JSON + text into evidence pack
`{{ pack_name }}`. Full command log: `run_log.txt`.

| Plugin | Status | Duration (s) |
|--------|--------|--------------|
{% for r in plugin_results -%}
| `{{ r.plugin }}` | {{ r.status }} | {{ r.duration_s }} |
{% endfor %}

## 4. Findings

[ANALYST: evidence-led narrative. Walk through what the data shows.]

### 4.1 Processes ({{ pslist|length }} in pslist)

{{ process_table }}

[ANALYST: anything anomalous? Odd parents, misspelled names, wrong paths,
processes in psscan missing from pslist?]

### 4.2 Network connections ({{ net_rows|length }} external endpoints)

{{ network_table }}

[ANALYST: which connections are C2 candidates and why?]

### 4.3 Injected code (malfind: {{ malfind_procs|length }} flagged processes)

{{ malfind_table }}

[ANALYST: interpret protections/headers — true injection or false positive?]

### 4.4 Persistence

[ANALYST: services (svcscan), run keys (registry), scheduled tasks.]

## 5. Timeline

[ANALYST: reconstructed sequence of attacker activity, oldest first.]

| Time (UTC) | Event | Evidence |
|------------|-------|----------|
| | | |

## 6. IOCs ({{ ioc_count }} candidates extracted)

{{ ioc_table }}

> IPs defanged. Machine-readable copy: `iocs.json` (ThreatLens-ready).

## 7. MITRE ATT&CK mapping

[ANALYST: keep only techniques actually observed, with the evidence for each.]

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|----------|
| Execution | Command and Scripting Interpreter | T1059 | |
| Defense Evasion | Process Injection | T1055 | |
| Defense Evasion | Masquerading | T1036 | |
| Command and Control | Application Layer Protocol | T1071 | |

## 8. Verdict & assessment

[ANALYST: conclusion + confidence level (high/medium/low) + what evidence
supports it and what would raise confidence.]

## 9. Recommendations

[ANALYST: containment, eradication, recovery, and hardening advice as you
would give a SOC: isolate host, block IOCs, reset credentials, etc.]
""")


def _md_table(rows: list[dict], columns: list[str], limit: int = 40) -> str:
    if not rows:
        return "_(no data captured for this plugin)_"
    header = "| " + " | ".join(columns) + " |"
    sep = "|" + "|".join(["---"] * len(columns)) + "|"
    body = []
    for row in rows[:limit]:
        cells = [str(row.get(c, "") if row.get(c) is not None else "") for c in columns]
        body.append("| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |")
    table = "\n".join([header, sep] + body)
    if len(rows) > limit:
        table += f"\n\n_({len(rows) - limit} more rows in the evidence pack JSON)_"
    return table


def generate_report(pack_dir: Path, case_name: str | None = None) -> Path:
    """Build the scaffold report from an evidence pack directory."""
    meta = json.loads((pack_dir / "image_metadata.json").read_text(encoding="utf-8"))
    try:
        plugin_results = json.loads((pack_dir / "plugin_results.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        plugin_results = []

    pslist = load_plugin_json(pack_dir, "windows.pslist")
    netscan = load_plugin_json(pack_dir, "windows.netscan")
    malfind = load_plugin_json(pack_dir, "windows.malfind")

    try:
        iocs_doc = json.loads((pack_dir / "iocs.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        iocs_doc = {"count": 0, "iocs": []}

    # External-only network rows, defanged for the report body.
    net_rows = []
    for row in netscan:
        foreign = str(row.get("ForeignAddr", "") or "")
        if is_external_ip(foreign):
            net_rows.append({
                "Process": row.get("Owner"), "PID": row.get("PID"),
                "Proto": row.get("Proto"), "LocalPort": row.get("LocalPort"),
                "Foreign": f"{defang_ip(foreign)}:{row.get('ForeignPort')}",
                "State": row.get("State"),
            })

    malfind_procs: dict = {}
    for row in malfind:
        key = (row.get("PID"), row.get("Process"))
        if key not in malfind_procs:
            malfind_procs[key] = {
                "Process": row.get("Process"), "PID": row.get("PID"),
                "Protection": row.get("Protection"),
                "StartVPN": row.get("Start VPN") or row.get("StartVPN"),
            }

    ioc_rows = [
        {
            "Type": i.get("type"),
            "Value": i.get("defanged") or i.get("value"),
            "PID": i.get("pid"),
            "Why flagged": i.get("reason") or f"port {i.get('port')} ({i.get('process')})",
        }
        for i in iocs_doc.get("iocs", [])
    ]

    os_details = meta.get("os_details", {})
    os_summary = (
        f"{meta.get('os_family', 'unknown')}"
        + (f" — NT {os_details.get('NtMajorVersion')}.{os_details.get('NtMinorVersion')}" if os_details.get("NtMajorVersion") is not None else "")
        + (f", build {os_details.get('NtBuildLab')}" if os_details.get("NtBuildLab") else "")
    )

    class _Meta:  # attribute access for the template
        def __init__(self, d): self.__dict__.update(d)

    class _Res:
        def __init__(self, d): self.__dict__.update(d)

    name = case_name or pack_dir.name
    content = TEMPLATE.render(
        case_name=name,
        meta=_Meta(meta),
        os_summary=os_summary,
        pack_name=pack_dir.name,
        plugin_results=[_Res(r) for r in plugin_results],
        pslist=pslist,
        process_table=_md_table(pslist, ["PID", "PPID", "ImageFileName", "CreateTime", "ExitTime"]),
        net_rows=net_rows,
        network_table=_md_table(net_rows, ["Process", "PID", "Proto", "LocalPort", "Foreign", "State"]),
        malfind_procs=malfind_procs,
        malfind_table=_md_table(list(malfind_procs.values()), ["Process", "PID", "Protection", "StartVPN"]),
        ioc_count=iocs_doc.get("count", 0),
        ioc_table=_md_table(ioc_rows, ["Type", "Value", "PID", "Why flagged"]),
    )

    out = pack_dir / "report_scaffold.md"
    out.write_text(content, encoding="utf-8")
    print(f"[+] Report scaffold -> {out}")
    return out
