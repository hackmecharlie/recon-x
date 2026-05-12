# ============================================================
# RECON-X | core/target_manager.py
# Description: Thread-safe target queue manager tracking state
#              of all targets through the scan lifecycle
# ============================================================

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Callable, Dict, Generator, List, Optional

from core.input_parser import Target

logger = logging.getLogger(__name__)


class TargetState(str, Enum):
    """Lifecycle states of a scan target."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


@dataclass
class ManagedTarget:
    """A Target wrapped with state tracking metadata."""
    target: Target
    state: TargetState = TargetState.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    worker_id: Optional[str] = None


class TargetManager:
    """Thread-safe manager for scan targets.

    Maintains a queue of targets and tracks their state throughout
    the scan. Integrates with the checkpoint system for resume support.
    """

    def __init__(
        self,
        targets: List[Target],
        skip_completed: Optional[List[str]] = None,
        on_state_change: Optional[Callable[["TargetManager"], None]] = None,
    ) -> None:
        """Initialize the target manager.

        Args:
            targets: List of Target objects to manage.
            skip_completed: List of IP/hostnames to skip (from checkpoint resume).
            on_state_change: Optional callback invoked after each state transition.
        """
        self._lock = threading.Lock()
        self._on_state_change = on_state_change
        self._managed: Dict[str, ManagedTarget] = {}
        self._pending_keys: List[str] = []

        skip_set = set(skip_completed or [])

        for target in targets:
            key = self._key(target)
            if key in skip_set:
                mt = ManagedTarget(target=target, state=TargetState.SKIPPED)
            else:
                mt = ManagedTarget(target=target, state=TargetState.PENDING)
                self._pending_keys.append(key)
            self._managed[key] = mt

        logger.info(
            "TargetManager initialized: %d total, %d pending, %d skipped",
            len(self._managed),
            len(self._pending_keys),
            len(skip_set),
        )

    @staticmethod
    def _key(target: Target) -> str:
        """Derive a stable key for a target."""
        return target.ip or target.hostname or target.original_input

    @property
    def total(self) -> int:
        """Total number of managed targets."""
        return len(self._managed)

    @property
    def pending_count(self) -> int:
        """Number of targets still waiting."""
        with self._lock:
            return len(self._pending_keys)

    @property
    def completed_count(self) -> int:
        """Number of completed targets (success)."""
        with self._lock:
            return sum(
                1
                for mt in self._managed.values()
                if mt.state == TargetState.COMPLETED
            )

    @property
    def failed_count(self) -> int:
        """Number of failed or timed-out targets."""
        with self._lock:
            return sum(
                1
                for mt in self._managed.values()
                if mt.state in (TargetState.FAILED, TargetState.TIMEOUT)
            )

    @property
    def in_progress_count(self) -> int:
        """Number of targets currently being scanned."""
        with self._lock:
            return sum(
                1
                for mt in self._managed.values()
                if mt.state == TargetState.IN_PROGRESS
            )

    def get_next(self) -> Optional[ManagedTarget]:
        """Pop and return the next pending target, marking it IN_PROGRESS.

        Returns:
            ManagedTarget if available, None if queue is empty.
        """
        with self._lock:
            if not self._pending_keys:
                return None
            key = self._pending_keys.pop(0)
            mt = self._managed[key]
            mt.state = TargetState.IN_PROGRESS
            mt.started_at = datetime.utcnow()
            logger.debug("Dispatched target %s to worker", key)
            return mt

    def mark_completed(self, target: Target, worker_id: Optional[str] = None) -> None:
        """Mark a target as successfully completed.

        Args:
            target: The target that finished.
            worker_id: Identifier of the worker that processed it.
        """
        key = self._key(target)
        with self._lock:
            mt = self._managed.get(key)
            if mt:
                mt.state = TargetState.COMPLETED
                mt.completed_at = datetime.utcnow()
                mt.worker_id = worker_id
                logger.debug("Target %s marked COMPLETED", key)
        if self._on_state_change:
            self._on_state_change(self)

    def mark_failed(
        self, target: Target, error: str = "", worker_id: Optional[str] = None
    ) -> None:
        """Mark a target as failed.

        Args:
            target: The target that failed.
            error: Human-readable error description.
            worker_id: Identifier of the worker that processed it.
        """
        key = self._key(target)
        with self._lock:
            mt = self._managed.get(key)
            if mt:
                mt.state = TargetState.FAILED
                mt.completed_at = datetime.utcnow()
                mt.error = error
                mt.worker_id = worker_id
                logger.warning("Target %s marked FAILED: %s", key, error)
        if self._on_state_change:
            self._on_state_change(self)

    def mark_timeout(self, target: Target, worker_id: Optional[str] = None) -> None:
        """Mark a target as timed out.

        Args:
            target: The target that timed out.
            worker_id: Identifier of the worker that processed it.
        """
        key = self._key(target)
        with self._lock:
            mt = self._managed.get(key)
            if mt:
                mt.state = TargetState.TIMEOUT
                mt.completed_at = datetime.utcnow()
                mt.worker_id = worker_id
                logger.warning("Target %s marked TIMEOUT", key)
        if self._on_state_change:
            self._on_state_change(self)

    def get_by_state(self, state: TargetState) -> List[ManagedTarget]:
        """Return all ManagedTargets in a given state.

        Args:
            state: The state to filter by.

        Returns:
            List of ManagedTarget objects.
        """
        with self._lock:
            return [mt for mt in self._managed.values() if mt.state == state]

    def get_all(self) -> List[ManagedTarget]:
        """Return all managed targets."""
        with self._lock:
            return list(self._managed.values())

    def snapshot(self) -> Dict[str, List[str]]:
        """Return a state snapshot suitable for checkpointing.

        Returns:
            Dict with keys: completed, failed, pending, in_progress,
            each containing a list of target keys.
        """
        with self._lock:
            snap: Dict[str, List[str]] = {
                "completed": [],
                "failed": [],
                "pending": [],
                "in_progress": [],
                "timeout": [],
                "skipped": [],
            }
            for key, mt in self._managed.items():
                snap[mt.state.value].append(key)
            return snap

    def is_done(self) -> bool:
        """Return True if all non-skipped targets have reached a terminal state."""
        with self._lock:
            for mt in self._managed.values():
                if mt.state in (TargetState.PENDING, TargetState.IN_PROGRESS):
                    return False
            return True

    def feed_from_generator(
        self, generator: Generator[Target, None, None]
    ) -> None:
        """Dynamically add targets from a generator into the pending queue.

        This allows streaming large CIDR expansions without pre-loading all
        targets into memory.

        Args:
            generator: Generator yielding Target objects.
        """
        for target in generator:
            key = self._key(target)
            with self._lock:
                if key not in self._managed:
                    mt = ManagedTarget(target=target, state=TargetState.PENDING)
                    self._managed[key] = mt
                    self._pending_keys.append(key)
