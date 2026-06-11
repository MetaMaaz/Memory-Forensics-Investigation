"""Tests for IOC extraction (FR4) — fixtures mimic Volatility 3 JSON rows."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import iocs  # noqa: E402


# --- IP classification / defanging -------------------------------------------

def test_external_ip_detection():
    assert iocs.is_external_ip("41.168.5.140")
    assert iocs.is_external_ip("8.8.8.8")
    assert not iocs.is_external_ip("192.168.1.10")      # private
    assert not iocs.is_external_ip("10.0.2.15")          # private
    assert not iocs.is_external_ip("127.0.0.1")          # loopback
    assert not iocs.is_external_ip("0.0.0.0")            # unspecified
    assert not iocs.is_external_ip("224.0.0.1")          # multicast
    assert not iocs.is_external_ip("not-an-ip")
    assert not iocs.is_external_ip("")


def test_defang_refang_roundtrip():
    assert iocs.defang_ip("41.168.5.140") == "41.168.5[.]140"
    assert iocs.refang_ip("41.168.5[.]140") == "41.168.5.140"


# --- Network IOCs (netscan fixture mirrors the Cridex case) -------------------

NETSCAN_ROWS = [
    {"Proto": "TCPv4", "LocalAddr": "172.16.112.128", "LocalPort": 1038,
     "ForeignAddr": "41.168.5.140", "ForeignPort": 8080, "State": "CLOSED",
     "PID": 1484, "Owner": "explorer.exe"},
    {"Proto": "TCPv4", "LocalAddr": "172.16.112.128", "LocalPort": 1037,
     "ForeignAddr": "125.19.103.198", "ForeignPort": 8080, "State": "CLOSED",
     "PID": 1484, "Owner": "explorer.exe"},
    {"Proto": "TCPv4", "LocalAddr": "0.0.0.0", "LocalPort": 445,
     "ForeignAddr": "0.0.0.0", "ForeignPort": 0, "State": "LISTENING",
     "PID": 4, "Owner": "System"},
    {"Proto": "TCPv4", "LocalAddr": "127.0.0.1", "LocalPort": 1025,
     "ForeignAddr": "127.0.0.1", "ForeignPort": 1026, "State": "ESTABLISHED",
     "PID": 660, "Owner": "svchost.exe"},
]


def test_network_iocs_external_only():
    out = iocs.extract_network_iocs(NETSCAN_ROWS)
    values = {i["value"] for i in out}
    assert values == {"41.168.5.140", "125.19.103.198"}
    assert all(i["defanged"].count("[.]") == 1 for i in out)
    assert out[0]["source_plugin"] == "windows.netscan"


def test_network_iocs_dedupe():
    out = iocs.extract_network_iocs(NETSCAN_ROWS + NETSCAN_ROWS)
    assert len(out) == 2


# --- Process IOCs -------------------------------------------------------------

PSLIST_ROWS = [
    {"PID": 4, "PPID": 0, "ImageFileName": "System"},
    {"PID": 1484, "PPID": 1464, "ImageFileName": "explorer.exe"},
    {"PID": 1640, "PPID": 1484, "ImageFileName": "reader_sl.exe"},
]

PSSCAN_ROWS = PSLIST_ROWS + [
    {"PID": 2044, "PPID": 1640, "ImageFileName": "ghost.exe"},
]


def test_suspicious_process_name_flagged():
    out = iocs.extract_process_iocs(PSLIST_ROWS)
    assert any(i["value"] == "reader_sl.exe" for i in out)
    assert all(i["value"] != "explorer.exe" for i in out)


def test_hidden_process_cross_view():
    out = iocs.extract_process_iocs(PSLIST_ROWS, PSSCAN_ROWS)
    hidden = [i for i in out if i["source_plugin"] == "windows.psscan"]
    assert len(hidden) == 1
    assert hidden[0]["value"] == "ghost.exe"
    assert hidden[0]["pid"] == 2044


# --- Command-line IOCs ----------------------------------------------------------

CMDLINE_ROWS = [
    {"PID": 1640, "Process": "reader_sl.exe",
     "Args": "C:\\Program Files\\Adobe\\Reader 9.0\\Reader\\Reader_sl.exe"},
    {"PID": 2100, "Process": "powershell.exe",
     "Args": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"},
    {"PID": 2200, "Process": "evil.exe",
     "Args": "C:\\Users\\victim\\AppData\\Local\\Temp\\evil.exe -install"},
    {"PID": 800, "Process": "svchost.exe",
     "Args": "C:\\WINDOWS\\system32\\svchost.exe -k netsvcs"},
]


def test_cmdline_lolbin_and_path_flags():
    out = iocs.extract_cmdline_iocs(CMDLINE_ROWS)
    by_pid = {i["pid"]: i for i in out}
    assert 2100 in by_pid and "LOLBin" in by_pid[2100]["reason"]
    assert 2200 in by_pid and "user-writable" in by_pid[2200]["reason"]
    assert 800 not in by_pid          # legitimate svchost not flagged
    assert 1640 not in by_pid         # legitimate program-files path not flagged


# --- Malfind IOCs ----------------------------------------------------------------

MALFIND_ROWS = [
    {"PID": 1484, "Process": "explorer.exe", "Start VPN": 5570560,
     "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 1, "PrivateMemory": 1},
    {"PID": 1484, "Process": "explorer.exe", "Start VPN": 9700000,
     "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 4, "PrivateMemory": 1},
    {"PID": 1640, "Process": "reader_sl.exe", "Start VPN": 4128768,
     "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 2, "PrivateMemory": 1},
    {"PID": 999, "Process": "benign.exe", "Start VPN": 1000,
     "Protection": "PAGE_READWRITE", "CommitCharge": 1, "PrivateMemory": 1},
]


def test_malfind_executable_regions_only():
    out = iocs.extract_malfind_iocs(MALFIND_ROWS)
    procs = {i["value"]: i for i in out}
    assert set(procs) == {"explorer.exe", "reader_sl.exe"}
    assert procs["explorer.exe"]["region_count"] == 2   # deduped per process


# --- End-to-end against a synthetic evidence pack --------------------------------

def test_extract_all_and_write(tmp_path):
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    (plugins / "windows_netscan.json").write_text(json.dumps(NETSCAN_ROWS))
    (plugins / "windows_pslist.json").write_text(json.dumps(PSLIST_ROWS))
    (plugins / "windows_psscan.json").write_text(json.dumps(PSSCAN_ROWS))
    (plugins / "windows_cmdline.json").write_text(json.dumps(CMDLINE_ROWS))
    (plugins / "windows_malfind.json").write_text(json.dumps(MALFIND_ROWS))

    out = iocs.write_iocs(tmp_path)
    doc = json.loads(out.read_text())
    assert doc["schema"] == "memory-forensics-iocs/v1"
    assert doc["count"] == len(doc["iocs"]) > 0
    types = {i["type"] for i in doc["iocs"]}
    assert {"ip", "process", "cmdline", "injected_code"} <= types


def test_missing_plugin_files_graceful(tmp_path):
    """An empty pack still produces a valid (empty) iocs.json — no crash."""
    doc = iocs.extract_all(tmp_path)
    assert doc["count"] == 0 and doc["iocs"] == []
