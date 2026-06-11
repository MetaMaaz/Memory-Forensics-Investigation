"""FR3 — Evidence pack assembly.

One analysed image -> one timestamped, self-contained evidence pack:

    evidence/<image-stem>_<UTC timestamp>/
    ├── image_metadata.json     # path, size, SHA256, OS, vol version, timestamps
    ├── run_log.txt             # every command executed (reproducibility)
    ├── plugin_results.json     # per-plugin status/duration/errors
    ├── plugins/                # one .json + .txt per plugin
    └── iocs.json               # extracted IOCs (written by iocs.py)
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from . import config
from .intake import ImageMetadata
from .runner import PluginResult


def create_pack_dir(image_path: Path, base: Path | None = None) -> Path:
    """Create a timestamped evidence pack directory for an image."""
    base = base or config.EVIDENCE_DIR
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    pack = base / f"{image_path.stem}_{stamp}"
    (pack / "plugins").mkdir(parents=True, exist_ok=True)
    return pack


def write_metadata(pack_dir: Path, metadata: ImageMetadata) -> Path:
    out = pack_dir / "image_metadata.json"
    out.write_text(metadata.to_json(), encoding="utf-8")
    return out


def write_plugin_results(pack_dir: Path, results: list[PluginResult]) -> Path:
    out = pack_dir / "plugin_results.json"
    out.write_text(
        json.dumps([asdict(r) for r in results], indent=2), encoding="utf-8"
    )
    return out


def load_plugin_json(pack_dir: Path, plugin: str) -> list[dict]:
    """Load a plugin's JSON rows from an evidence pack ([] if missing/empty)."""
    path = pack_dir / "plugins" / f"{plugin.replace('.', '_')}.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def pack_summary(pack_dir: Path) -> dict:
    """Small machine-readable summary of what the pack contains."""
    plugins_dir = pack_dir / "plugins"
    files = sorted(p.name for p in plugins_dir.glob("*.json")) if plugins_dir.is_dir() else []
    return {
        "pack": str(pack_dir),
        "plugin_outputs": files,
        "has_iocs": (pack_dir / "iocs.json").is_file(),
        "has_run_log": (pack_dir / "run_log.txt").is_file(),
    }
