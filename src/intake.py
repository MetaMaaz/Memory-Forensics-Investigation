"""FR1 — Image intake: hashing, metadata, OS detection, integrity verification.

Chain-of-custody approach: the image is treated as read-only evidence. We hash
it (SHA256) before any analysis, record the hash in the evidence pack, and
re-hash after the run to assert the image was not modified.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import config


class IntegrityError(Exception):
    """Raised when the post-run hash does not match the pre-run hash."""


@dataclass
class ImageMetadata:
    path: str
    filename: str
    size_bytes: int
    sha256: str
    os_family: str = "unknown"          # "windows" | "linux" | "unknown"
    os_details: dict = field(default_factory=dict)
    volatility_version: str = ""
    analysed_at_utc: str = ""
    sha256_verified_after_run: bool = False

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Stream-hash a file (images can be multi-GB; never load into RAM)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_image_path(image_path: Path) -> Path:
    image_path = image_path.expanduser().resolve()
    if not image_path.is_file():
        raise FileNotFoundError(f"Memory image not found: {image_path}")
    if image_path.suffix.lower() not in config.IMAGE_EXTENSIONS:
        # Warn-don't-block: extensions vary in the wild.
        print(
            f"[!] Unusual extension '{image_path.suffix}' — proceeding anyway "
            f"(accepted: {', '.join(sorted(config.IMAGE_EXTENSIONS))})"
        )
    return image_path


def volatility_version() -> str:
    """Return the installed Volatility 3 version string."""
    try:
        out = subprocess.run(
            ["vol", "--help"], capture_output=True, text=True, timeout=60
        )
        # First line looks like: "Volatility 3 Framework 2.26.0"
        for line in (out.stdout + out.stderr).splitlines():
            if "Volatility 3 Framework" in line:
                return line.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return "unknown (is volatility3 installed? `pip install volatility3`)"


def detect_os(image_path: Path, run_cmd) -> tuple[str, dict]:
    """Detect the image's OS family.

    Strategy (SPEC FR1): try `windows.info` first (Windows symbols
    auto-download, so this is the cheap, common case). If that fails, try
    `banners.Banners` which reveals Linux kernel banners.

    `run_cmd` is injected (signature: (plugin: str) -> (rc, stdout, stderr))
    so this stays testable and all commands flow through the run log.
    """
    rc, stdout, _ = run_cmd("windows.info")
    if rc == 0 and stdout.strip():
        details = _parse_windows_info(stdout)
        if details:
            return "windows", details

    rc, stdout, _ = run_cmd("banners.Banners")
    if rc == 0 and "Linux" in stdout:
        banner_lines = [l for l in stdout.splitlines() if "Linux" in l]
        return "linux", {"banners": banner_lines[:5]}

    return "unknown", {}


def _parse_windows_info(stdout: str) -> dict:
    """Parse `windows.info` JSON output into a {Variable: Value} dict."""
    details: dict = {}
    try:
        rows = json.loads(stdout)
        for row in rows:
            var, val = row.get("Variable"), row.get("Value")
            if var:
                details[var] = val
    except (json.JSONDecodeError, AttributeError, TypeError):
        # Fall back to raw text capture if the renderer wasn't JSON.
        for line in stdout.splitlines():
            if "\t" in line:
                parts = line.split("\t")
                if len(parts) >= 2:
                    details[parts[0].strip()] = parts[1].strip()
    return details


def build_metadata(image_path: Path) -> ImageMetadata:
    """Hash the image and assemble initial metadata (pre-analysis)."""
    image_path = validate_image_path(image_path)
    print(f"[*] Hashing image (SHA256): {image_path.name} ...")
    digest = sha256_file(image_path)
    print(f"[*] SHA256: {digest}")
    return ImageMetadata(
        path=str(image_path),
        filename=image_path.name,
        size_bytes=image_path.stat().st_size,
        sha256=digest,
        volatility_version=volatility_version(),
        analysed_at_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


def verify_integrity(metadata: ImageMetadata) -> None:
    """Re-hash after analysis; raise if the evidence was modified (FR1)."""
    print("[*] Re-hashing image to verify evidence integrity ...")
    post_hash = sha256_file(Path(metadata.path))
    if post_hash != metadata.sha256:
        raise IntegrityError(
            f"EVIDENCE INTEGRITY FAILURE: pre-run SHA256 {metadata.sha256} "
            f"!= post-run {post_hash}. The image was modified during analysis."
        )
    metadata.sha256_verified_after_run = True
    print("[+] Integrity verified: image unchanged (read-only analysis confirmed).")
