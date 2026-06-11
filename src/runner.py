"""FR2 — Plugin runner: drive Volatility 3 via subprocess, capture output.

Design points (per SPEC):
- Every command executed is appended to run_log.txt (reproducibility).
- Each plugin's output is captured twice: machine-readable JSON (`-r json`)
  and a human-readable text copy.
- One plugin failing never aborts the run; failures are logged and reported.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import config


@dataclass
class PluginResult:
    plugin: str
    rationale: str
    status: str          # "ok" | "error" | "timeout" | "empty"
    duration_s: float
    json_path: str = ""
    txt_path: str = ""
    error: str = ""


@dataclass
class RunLog:
    """Append-only log of every command executed (chain-of-custody artefact)."""

    path: Path
    lines: list[str] = field(default_factory=list)

    def record(self, message: str) -> None:
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        line = f"[{stamp}] {message}"
        self.lines.append(line)
        print(line)
        # Flush to disk on every entry so a crash still leaves a usable log.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def vol_command(image_path: Path, plugin: str, renderer: str = "json") -> list[str]:
    """Build the exact Volatility 3 command line for a plugin."""
    cmd = ["vol", "-q"]
    if renderer:
        cmd += ["-r", renderer]
    cmd += ["-f", str(image_path), plugin]
    return cmd


def run_vol(
    image_path: Path,
    plugin: str,
    run_log: RunLog,
    renderer: str = "json",
    timeout: int = config.PLUGIN_TIMEOUT,
) -> tuple[int, str, str]:
    """Run one Volatility plugin; return (returncode, stdout, stderr)."""
    cmd = vol_command(image_path, plugin, renderer)
    run_log.record(f"EXEC: {' '.join(cmd)}")
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        run_log.record(f"TIMEOUT after {timeout}s: {plugin}")
        return -1, "", f"timeout after {timeout}s"
    except FileNotFoundError:
        run_log.record("FATAL: `vol` not found — is volatility3 installed?")
        return -2, "", "vol executable not found"


def json_to_text_table(json_output: str) -> str:
    """Render Volatility JSON rows as an aligned text table (human copy)."""
    import json as _json

    try:
        rows = _json.loads(json_output)
    except _json.JSONDecodeError:
        return json_output  # already text / unparsable — keep as-is
    if not isinstance(rows, list) or not rows:
        return "(no rows)"

    headers = [k for k in rows[0].keys() if k != "__children"]
    flat: list[dict] = []

    def _flatten(items: list[dict], depth: int = 0) -> None:
        for item in items:
            row = {k: item.get(k) for k in headers}
            row["__depth"] = depth
            flat.append(row)
            children = item.get("__children") or []
            if children:
                _flatten(children, depth + 1)

    _flatten(rows)

    widths = {h: len(h) for h in headers}
    rendered: list[list[str]] = []
    for row in flat:
        cells = []
        for i, h in enumerate(headers):
            val = "" if row.get(h) is None else str(row.get(h))
            if i == 0 and row["__depth"]:
                val = "  " * row["__depth"] + "* " + val
            widths[h] = max(widths[h], len(val))
            cells.append(val)
        rendered.append(cells)

    out = ["  ".join(h.ljust(widths[h]) for h in headers)]
    out.append("  ".join("-" * widths[h] for h in headers))
    for cells in rendered:
        out.append("  ".join(c.ljust(widths[h]) for c, h in zip(cells, headers)))
    if len(out) > config.TXT_TRUNCATE_LINES:
        kept = out[: config.TXT_TRUNCATE_LINES]
        kept.append(f"... truncated ({len(out) - config.TXT_TRUNCATE_LINES} more lines; full data in the .json file)")
        out = kept
    return "\n".join(out)


def run_plugin_set(
    image_path: Path,
    plugins: list[tuple[str, str]],
    output_dir: Path,
    run_log: RunLog,
) -> list[PluginResult]:
    """Run the curated plugin set, capturing JSON + txt per plugin (FR2)."""
    results: list[PluginResult] = []
    output_dir.mkdir(parents=True, exist_ok=True)

    for plugin, rationale in plugins:
        start = time.monotonic()
        rc, stdout, stderr = run_vol(image_path, plugin, run_log)
        duration = round(time.monotonic() - start, 2)
        safe_name = plugin.replace(".", "_")
        result = PluginResult(plugin=plugin, rationale=rationale, status="ok", duration_s=duration)

        if rc != 0 or not stdout.strip():
            result.status = "timeout" if "timeout" in stderr else "error" if rc != 0 else "empty"
            result.error = (stderr.strip() or "no output").splitlines()[-1][:500]
            run_log.record(f"PLUGIN {plugin}: {result.status.upper()} ({result.error})")
            results.append(result)
            continue  # graceful degradation — never abort the run (NFR)

        json_path = output_dir / f"{safe_name}.json"
        txt_path = output_dir / f"{safe_name}.txt"
        json_path.write_text(stdout, encoding="utf-8")
        txt_path.write_text(json_to_text_table(stdout), encoding="utf-8")
        result.json_path = str(json_path)
        result.txt_path = str(txt_path)
        run_log.record(f"PLUGIN {plugin}: OK in {duration}s -> {json_path.name}")
        results.append(result)

    ok = sum(1 for r in results if r.status == "ok")
    run_log.record(f"SUMMARY: {ok}/{len(results)} plugins succeeded")
    return results
