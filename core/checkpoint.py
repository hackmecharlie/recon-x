# ============================================================
# RECON-X | core/checkpoint.py
# Description: Atomic checkpoint save/load for scan resume support.
#              Writes .tmp then renames to prevent corruption.
# ============================================================

import json
import logging
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_CHECKPOINT_FILENAME = "checkpoint.json"
_TMP_SUFFIX = ".tmp"


@dataclass
class CheckpointData:
    """Serializable checkpoint containing scan progress and partial findings."""

    scan_id: str
    title: str
    started_at: str  # ISO format
    total_targets: int
    completed: List[str] = field(default_factory=list)
    failed: List[str] = field(default_factory=list)
    timeout: List[str] = field(default_factory=list)
    pending: List[str] = field(default_factory=list)
    in_progress: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    scan_profile: str = "normal"
    output_dir: str = "./output"


def _datetime_serializer(obj: Any) -> str:
    """JSON serializer for datetime objects."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


class CheckpointManager:
    """Manages saving and loading scan checkpoints.

    Checkpoints are written atomically: first to a .tmp file,
    then renamed to the final checkpoint.json to prevent corruption.
    """

    def __init__(self, output_dir: str) -> None:
        """Initialize checkpoint manager for a given output directory.

        Args:
            output_dir: Directory where the checkpoint file will be stored.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._checkpoint_path = self.output_dir / _CHECKPOINT_FILENAME
        self._tmp_path = self.output_dir / (_CHECKPOINT_FILENAME + _TMP_SUFFIX)

    def save(self, data: CheckpointData) -> None:
        """Atomically save checkpoint data.

        Writes to a temporary file first, then renames to prevent
        partial writes from corrupting the checkpoint.

        Args:
            data: CheckpointData instance to serialize and save.
        """
        try:
            payload = asdict(data)
            json_str = json.dumps(payload, indent=2, default=_datetime_serializer)
            self._tmp_path.write_text(json_str, encoding="utf-8")
            self._tmp_path.rename(self._checkpoint_path)
            logger.debug("Checkpoint saved to %s", self._checkpoint_path)
        except (OSError, TypeError) as exc:
            logger.error("Failed to save checkpoint: %s", exc)

    def load(self) -> Optional[CheckpointData]:
        """Load checkpoint data from disk.

        Returns:
            CheckpointData if checkpoint exists and is valid, else None.
        """
        if not self._checkpoint_path.exists():
            return None
        try:
            raw = self._checkpoint_path.read_text(encoding="utf-8")
            payload = json.loads(raw)
            return CheckpointData(**payload)
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            logger.error("Failed to load checkpoint from %s: %s", self._checkpoint_path, exc)
            return None

    def delete(self) -> None:
        """Delete the checkpoint file (called on clean completion)."""
        try:
            if self._checkpoint_path.exists():
                self._checkpoint_path.unlink()
            if self._tmp_path.exists():
                self._tmp_path.unlink()
            logger.debug("Checkpoint deleted")
        except OSError as exc:
            logger.warning("Failed to delete checkpoint: %s", exc)


def scan_for_incomplete_checkpoints(base_output_dir: str) -> List[tuple[Path, CheckpointData]]:
    """Scan the output directory for incomplete checkpoint files.

    Args:
        base_output_dir: Base directory to search for scan subdirectories.

    Returns:
        List of (directory_path, CheckpointData) tuples for incomplete scans.
    """
    base = Path(base_output_dir)
    results: List[tuple[Path, CheckpointData]] = []

    if not base.exists():
        return results

    for subdir in sorted(base.iterdir()):
        if not subdir.is_dir():
            continue
        cp_file = subdir / _CHECKPOINT_FILENAME
        if not cp_file.exists():
            continue
        try:
            raw = cp_file.read_text(encoding="utf-8")
            payload = json.loads(raw)
            data = CheckpointData(**payload)
            # Only return incomplete scans (pending targets remain)
            if data.pending or data.in_progress:
                results.append((subdir, data))
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            logger.debug("Skipping malformed checkpoint at %s: %s", cp_file, exc)

    return results


def new_scan_id() -> str:
    """Generate a new unique scan ID."""
    return str(uuid.uuid4())


def _slugify(text: str, max_length: int = 40) -> str:
    """Create a filesystem-safe slug from a title.

    This is used to include the scan title in the output folder name.
    """
    # Normalize spaces and remove unsafe filesystem characters
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", text.strip())
    slug = re.sub(r"_+", "_", slug)
    slug = slug.strip("_")
    if len(slug) > max_length:
        slug = slug[:max_length].rstrip("_")
    return slug or "scan"


def make_output_dir(base_dir: str, scan_id: str, scan_title: str | None = None) -> str:
    """Create and return the output directory for a scan.

    Args:
        base_dir: Base output directory.
        scan_id: Unique scan identifier.
        scan_title: Optional report title to include in folder name.

    Returns:
        Path to the created output directory.
    """
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    title_part = ""
    if scan_title:
        title_part = f"_{_slugify(scan_title)}"

    scan_dir = Path(base_dir) / f"scan_{ts}{title_part}_{scan_id[:8]}"
    scan_dir.mkdir(parents=True, exist_ok=True)
    screenshots_dir = scan_dir / "screenshots"
    screenshots_dir.mkdir(exist_ok=True)
    return str(scan_dir)
