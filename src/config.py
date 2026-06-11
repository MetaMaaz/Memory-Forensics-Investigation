"""Configuration: curated plugin sets, paths, and environment-driven options.

The plugin lists below are the single place to add/remove plugins (SPEC FR2).
Order matters — it mirrors a sensible triage order, so the run log reads like
an investigation: identify the OS, enumerate processes, then pivot to network,
injection, and persistence.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# --- Paths -----------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
IMAGES_DIR = PROJECT_ROOT / "images"
EVIDENCE_DIR = PROJECT_ROOT / "evidence"

# Accepted memory-image extensions (FR1).
IMAGE_EXTENSIONS = {".raw", ".mem", ".lime", ".dmp", ".vmem", ".bin", ".img"}

# --- Curated plugin sets (SPEC §5) ------------------------------------------
# (plugin, why it matters) — the rationale is surfaced in the run log and docs.

WINDOWS_PLUGINS: list[tuple[str, str]] = [
    ("windows.info", "OS/build sanity check — confirms the image parsed correctly"),
    ("windows.pslist", "processes from the active process list (what the OS admits to)"),
    ("windows.psscan", "pool-scanned processes — finds hidden/unlinked/terminated procs pslist misses"),
    ("windows.pstree", "parent/child relationships — odd parentage is a classic malware tell"),
    ("windows.cmdline", "process command lines — often the smoking gun for how something launched"),
    ("windows.netscan", "pool-scanned network connections incl. closed/hidden — external C2 IOCs"),
    ("windows.netstat", "live network state at capture time (complements netscan)"),
    ("windows.dlllist", "loaded modules per process — unsigned/odd-path DLLs"),
    ("windows.malfind", "RWX private memory with no file backing — classic code-injection detector"),
    ("windows.svcscan", "services — persistence via service creation/modification"),
    ("windows.registry.hivelist", "registry hives in memory — basis for run-key/persistence pivots"),
    ("windows.handles", "open handles for suspect processes — files, keys, mutexes"),
]

LINUX_PLUGINS: list[tuple[str, str]] = [
    ("linux.pslist", "running processes"),
    ("linux.pstree", "process ancestry"),
    ("linux.bash", "recovered bash history from memory"),
    ("linux.netstat", "network connections"),
    ("linux.malfind", "injected code detection"),
    ("linux.check_syscall", "syscall-table hooking (rootkit check)"),
]

# Plugins whose JSON output can be very large; the runner still captures them
# but truncates the human-readable .txt copy at this many lines.
TXT_TRUNCATE_LINES = 2000

# Per-plugin timeout in seconds. windows.handles on a big image can be slow.
PLUGIN_TIMEOUT = 900

# --- Optional ThreatLens enrichment hand-off (FR4) ---------------------------

THREATLENS_BASE_URL = os.getenv("THREATLENS_BASE_URL", "").strip()
THREATLENS_API_KEY = os.getenv("THREATLENS_API_KEY", "").strip()


def plugins_for_os(os_family: str) -> list[tuple[str, str]]:
    """Return the curated plugin list for a detected OS family."""
    if os_family == "linux":
        return LINUX_PLUGINS
    return WINDOWS_PLUGINS
