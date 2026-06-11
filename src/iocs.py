"""FR4 — Light IOC extraction from plugin output.

Pulls candidate IOCs out of the evidence pack:
- external IPs + ports (netscan/netstat)
- suspicious process names (masquerading, odd paths, known-bad names)
- command lines and file paths worth an analyst's attention
- processes flagged by malfind (injected code regions)

Deliberately *light*: it surfaces candidates for the analyst, it does not
score or conclude (SPEC non-goal: no automated verdicts).
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

from . import config

# Windows system processes expected to live in specific parent/path contexts.
# A name here appearing with a *different* path/extension is a masquerading flag.
KNOWN_SYSTEM_NAMES = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe", "taskhost.exe",
    "taskhostw.exe", "spoolsv.exe", "dwm.exe", "conhost.exe", "runtimebroker.exe",
}

# Name patterns that warrant analyst attention when seen in a memory image.
SUSPICIOUS_NAME_PATTERNS = [
    re.compile(r"^[a-z0-9]{8,}\.exe$", re.I),       # random-looking names
    re.compile(r"\.(scr|pif|bat|vbs|js)$", re.I),    # script/screensaver execution
    re.compile(r"^(reader_sl|kb\d{6,})", re.I),      # classic dropper names
]

# Paths user-writable locations malware launches from.
SUSPICIOUS_PATH_PATTERN = re.compile(
    r"\\(temp|tmp|appdata|downloads|public|programdata|recycler|\$recycle\.bin)\\",
    re.I,
)

LOLBIN_CMDLINE_PATTERN = re.compile(
    r"(powershell.*(-enc|-e\s|downloadstring|iex)|cmd\.exe\s*/c|rundll32|regsvr32.*scrobj|"
    r"mshta|certutil.*(-urlcache|-decode)|bitsadmin|wscript|cscript)",
    re.I,
)


def is_external_ip(value: str) -> bool:
    """True for routable, non-private, non-reserved IPs (the IOC-worthy ones)."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def defang_ip(ip: str) -> str:
    """1.2.3.4 -> 1.2.3[.]4 — safe to paste into reports/chat (FR4)."""
    parts = ip.rsplit(".", 1)
    return "[.]".join(parts) if len(parts) == 2 else ip


def refang_ip(ip: str) -> str:
    return ip.replace("[.]", ".")


def extract_network_iocs(netscan_rows: list[dict]) -> list[dict]:
    """External endpoints from netscan/netstat JSON rows."""
    seen: dict[tuple, dict] = {}
    for row in netscan_rows:
        foreign = str(row.get("ForeignAddr", "") or "")
        if not is_external_ip(foreign):
            continue
        key = (foreign, row.get("ForeignPort"), row.get("PID"))
        if key in seen:
            continue
        seen[key] = {
            "type": "ip",
            "value": foreign,
            "defanged": defang_ip(foreign),
            "port": row.get("ForeignPort"),
            "protocol": row.get("Proto"),
            "state": row.get("State"),
            "pid": row.get("PID"),
            "process": row.get("Owner"),
            "source_plugin": "windows.netscan",
        }
    return list(seen.values())


def extract_process_iocs(pslist_rows: list[dict], psscan_rows: list[dict] | None = None) -> list[dict]:
    """Suspicious process names + processes hidden from the active list."""
    iocs: list[dict] = []
    for row in pslist_rows:
        name = str(row.get("ImageFileName", "") or "")
        if name.lower() in KNOWN_SYSTEM_NAMES:
            continue  # expected names are checked for masquerading elsewhere, not here
        for pat in SUSPICIOUS_NAME_PATTERNS:
            if pat.search(name):
                iocs.append({
                    "type": "process",
                    "value": name,
                    "pid": row.get("PID"),
                    "ppid": row.get("PPID"),
                    "reason": f"name matches suspicious pattern {pat.pattern!r}",
                    "source_plugin": "windows.pslist",
                })
                break

    # Cross-view detection: in psscan but not pslist => hidden/terminated.
    if psscan_rows:
        listed_pids = {row.get("PID") for row in pslist_rows}
        for row in psscan_rows:
            pid = row.get("PID")
            if pid is not None and pid not in listed_pids:
                iocs.append({
                    "type": "process",
                    "value": str(row.get("ImageFileName", "") or ""),
                    "pid": pid,
                    "ppid": row.get("PPID"),
                    "reason": "present in psscan but absent from pslist (hidden or recently terminated)",
                    "source_plugin": "windows.psscan",
                })
    return iocs


def extract_cmdline_iocs(cmdline_rows: list[dict]) -> list[dict]:
    """Command lines featuring LOLBin abuse or user-writable launch paths."""
    iocs: list[dict] = []
    for row in cmdline_rows:
        cmd = str(row.get("Args", "") or "")
        if not cmd:
            continue
        reasons = []
        if LOLBIN_CMDLINE_PATTERN.search(cmd):
            reasons.append("LOLBin / scripting-interpreter abuse pattern")
        if SUSPICIOUS_PATH_PATTERN.search(cmd):
            reasons.append("executes from user-writable path (Temp/AppData/etc.)")
        if reasons:
            iocs.append({
                "type": "cmdline",
                "value": cmd[:500],
                "pid": row.get("PID"),
                "process": row.get("Process"),
                "reason": "; ".join(reasons),
                "source_plugin": "windows.cmdline",
            })
    return iocs


def extract_malfind_iocs(malfind_rows: list[dict]) -> list[dict]:
    """Processes with RWX private memory regions (injection candidates)."""
    seen: dict[tuple, dict] = {}
    for row in malfind_rows:
        pid = row.get("PID")
        proc = str(row.get("Process", "") or "")
        protection = str(row.get("Protection", "") or "")
        if "EXECUTE" not in protection.upper():
            continue
        key = (pid, proc)
        if key in seen:
            seen[key]["region_count"] += 1
            continue
        seen[key] = {
            "type": "injected_code",
            "value": proc,
            "pid": pid,
            "protection": protection,
            "start_vpn": row.get("Start VPN") or row.get("StartVPN"),
            "region_count": 1,
            "reason": "executable private memory region with no file backing (malfind)",
            "source_plugin": "windows.malfind",
        }
    return list(seen.values())


def extract_all(pack_dir: Path) -> dict:
    """Run every extractor against an evidence pack; return the iocs document."""
    from .evidence import load_plugin_json  # local import avoids cycle

    netscan = load_plugin_json(pack_dir, "windows.netscan") + load_plugin_json(pack_dir, "windows.netstat")
    pslist = load_plugin_json(pack_dir, "windows.pslist")
    psscan = load_plugin_json(pack_dir, "windows.psscan")
    cmdline = load_plugin_json(pack_dir, "windows.cmdline")
    malfind = load_plugin_json(pack_dir, "windows.malfind")

    iocs = (
        extract_network_iocs(netscan)
        + extract_process_iocs(pslist, psscan)
        + extract_cmdline_iocs(cmdline)
        + extract_malfind_iocs(malfind)
    )
    return {
        "schema": "memory-forensics-iocs/v1",
        "pack": pack_dir.name,
        "count": len(iocs),
        "iocs": iocs,
        "note": "Candidate IOCs for analyst review — extraction is heuristic, not a verdict.",
    }


def write_iocs(pack_dir: Path) -> Path:
    doc = extract_all(pack_dir)
    out = pack_dir / "iocs.json"
    out.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print(f"[+] {doc['count']} candidate IOCs -> {out}")
    return out


def submit_to_threatlens(iocs_path: Path) -> bool:
    """Optional hand-off to ThreatLens (FR4). Skips cleanly when unconfigured."""
    if not config.THREATLENS_BASE_URL:
        print("[*] ThreatLens not configured (THREATLENS_BASE_URL unset) — skipping enrichment.")
        return False
    import requests  # imported lazily so offline runs never need it

    url = config.THREATLENS_BASE_URL.rstrip("/") + "/api/iocs/import"
    headers = {"Content-Type": "application/json"}
    if config.THREATLENS_API_KEY:
        headers["Authorization"] = f"Bearer {config.THREATLENS_API_KEY}"
    try:
        resp = requests.post(
            url, data=iocs_path.read_text(encoding="utf-8"),
            headers=headers, timeout=15,
        )
        print(f"[+] ThreatLens hand-off: HTTP {resp.status_code}")
        return resp.ok
    except requests.RequestException as exc:
        print(f"[!] ThreatLens hand-off failed (non-fatal): {exc}")
        return False
