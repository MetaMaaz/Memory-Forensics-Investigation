"""CLI entry point: image in -> evidence pack + IOCs + report scaffold out.

Usage:
    python -m src.cli analyze images/<image>          # full pipeline
    python -m src.cli analyze images/<image> --no-report
    python -m src.cli iocs evidence/<pack>            # re-extract IOCs only
    python -m src.cli report evidence/<pack>          # re-scaffold report only
"""

from __future__ import annotations

from pathlib import Path

import typer

from . import config, evidence, intake, iocs, report
from .runner import RunLog, run_plugin_set, run_vol

app = typer.Typer(add_completion=False, help="Memory forensics evidence-pack pipeline (Volatility 3).")


@app.command()
def analyze(
    image: Path = typer.Argument(..., help="Path to the memory image (.raw/.mem/.vmem/.dmp/...)"),
    threatlens: bool = typer.Option(False, "--threatlens", help="POST iocs.json to ThreatLens (needs .env)"),
    make_report: bool = typer.Option(True, "--report/--no-report", help="Generate the report scaffold"),
) -> None:
    """Full pipeline: hash -> detect OS -> run plugins -> evidence pack -> IOCs -> report."""
    image = intake.validate_image_path(image)

    # 1. Intake: hash + metadata (FR1)
    meta = intake.build_metadata(image)

    # 2. Evidence pack dir + run log (FR3)
    pack = evidence.create_pack_dir(image)
    run_log = RunLog(pack / "run_log.txt")
    run_log.record(f"START analysis of {image} (SHA256={meta.sha256})")
    run_log.record(f"Volatility: {meta.volatility_version}")

    # 3. OS detection (FR1) — all commands flow through the run log
    os_family, os_details = intake.detect_os(
        image, lambda plugin: run_vol(image, plugin, run_log)
    )
    meta.os_family, meta.os_details = os_family, os_details
    run_log.record(f"Detected OS family: {os_family}")
    if os_family == "unknown":
        run_log.record("WARNING: OS detection failed — defaulting to the Windows plugin set. "
                       "Check symbols (Linux images need an ISF table).")

    # 4. Curated plugin set (FR2)
    plugins = config.plugins_for_os(os_family)
    results = run_plugin_set(image, plugins, pack / "plugins", run_log)
    evidence.write_plugin_results(pack, results)

    # 5. Integrity re-verification (FR1) — evidence must be unchanged
    intake.verify_integrity(meta)
    run_log.record("Integrity check passed: post-run SHA256 matches pre-run hash.")
    evidence.write_metadata(pack, meta)

    # 6. IOC extraction (FR4)
    iocs_path = iocs.write_iocs(pack)
    if threatlens:
        iocs.submit_to_threatlens(iocs_path)

    # 7. Report scaffold (FR5)
    if make_report:
        report.generate_report(pack)

    ok = sum(1 for r in results if r.status == "ok")
    typer.echo(f"\n[DONE] Evidence pack: {pack}")
    typer.echo(f"       Plugins: {ok}/{len(results)} ok | IOCs: see iocs.json | Report: report_scaffold.md")
    if ok < len(results):
        failed = ", ".join(r.plugin for r in results if r.status != "ok")
        typer.echo(f"       Non-fatal failures: {failed} (details in run_log.txt)")


@app.command("iocs")
def iocs_cmd(pack: Path = typer.Argument(..., help="Evidence pack directory")) -> None:
    """(Re-)extract IOCs from an existing evidence pack."""
    iocs.write_iocs(pack)


@app.command("report")
def report_cmd(
    pack: Path = typer.Argument(..., help="Evidence pack directory"),
    case_name: str = typer.Option(None, "--case-name", help="Title for the report"),
) -> None:
    """(Re-)generate the report scaffold from an existing evidence pack."""
    report.generate_report(pack, case_name)


if __name__ == "__main__":
    app()
