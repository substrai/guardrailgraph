"""Custom check hot-reload without pipeline restart.

File watcher that reloads @check functions on change, enabling
zero-downtime updates to guardrail checks in development and
production environments.

Usage:
    from guardrailgraph.pipeline.hot_reload import HotReloader

    reloader = HotReloader(watch_dirs=["./checks"])
    reloader.start()

    # When a check file changes, the pipeline automatically picks up
    # the new version without restarting.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import os
import sys
import time
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set


@dataclass
class CheckModule:
    """Tracks a loaded check module and its state."""

    path: str
    module_name: str
    last_modified: float
    content_hash: str
    checks: List[str] = field(default_factory=list)
    load_error: Optional[str] = None
    reload_count: int = 0


@dataclass
class ReloadEvent:
    """Record of a reload event."""

    timestamp: float
    path: str
    module_name: str
    success: bool
    checks_updated: List[str]
    error: Optional[str] = None
    duration_ms: float = 0.0


class HotReloader:
    """File watcher that reloads @check functions on change.

    Monitors specified directories for Python file changes and
    automatically reloads check functions when modifications are
    detected. Provides zero-downtime updates for guardrail checks.

    Args:
        watch_dirs: Directories to monitor for check file changes.
        poll_interval: Seconds between file system polls.
        on_reload: Optional callback invoked after successful reload.
        on_error: Optional callback invoked on reload failure.
        auto_start: Whether to start watching immediately.
    """

    def __init__(
        self,
        watch_dirs: Optional[List[str]] = None,
        poll_interval: float = 1.0,
        on_reload: Optional[Callable[[ReloadEvent], None]] = None,
        on_error: Optional[Callable[[ReloadEvent], None]] = None,
        auto_start: bool = False,
    ):
        self._watch_dirs = [Path(d) for d in (watch_dirs or ["./checks"])]
        self._poll_interval = poll_interval
        self._on_reload = on_reload
        self._on_error = on_error
        self._modules: Dict[str, CheckModule] = {}
        self._check_registry: Dict[str, Any] = {}
        self._events: List[ReloadEvent] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Initial scan
        self._scan_all()

        if auto_start:
            self.start()

    @property
    def watched_modules(self) -> Dict[str, CheckModule]:
        """Get all watched modules and their states."""
        return self._modules.copy()

    @property
    def check_registry(self) -> Dict[str, Any]:
        """Get the current check function registry."""
        return self._check_registry.copy()

    @property
    def events(self) -> List[ReloadEvent]:
        """Get reload event history."""
        return self._events.copy()

    @property
    def is_running(self) -> bool:
        """Whether the file watcher is currently active."""
        return self._running

    def start(self) -> None:
        """Start the file watcher thread."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._watch_loop,
            daemon=True,
            name="guardrailgraph-hot-reloader",
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the file watcher thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self._poll_interval * 2)
        self._thread = None

    def reload_module(self, path: str) -> ReloadEvent:
        """Manually reload a specific module.

        Args:
            path: Path to the Python file to reload.

        Returns:
            ReloadEvent with the result.
        """
        return self._reload_file(Path(path))

    def get_check(self, name: str) -> Optional[Any]:
        """Get a check function by name from the registry.

        Args:
            name: The check function name.

        Returns:
            The check function, or None if not found.
        """
        return self._check_registry.get(name)

    def _watch_loop(self) -> None:
        """Main watch loop — polls for file changes."""
        while self._running:
            try:
                self._check_for_changes()
            except Exception:
                pass  # Don't crash the watcher on unexpected errors
            time.sleep(self._poll_interval)

    def _check_for_changes(self) -> None:
        """Check all watched files for modifications."""
        for watch_dir in self._watch_dirs:
            if not watch_dir.exists():
                continue

            for py_file in watch_dir.rglob("*.py"):
                if py_file.name.startswith("_"):
                    continue

                file_key = str(py_file.resolve())
                current_mtime = py_file.stat().st_mtime

                if file_key in self._modules:
                    if current_mtime > self._modules[file_key].last_modified:
                        # File changed — reload
                        self._reload_file(py_file)
                else:
                    # New file — load it
                    self._load_file(py_file)

    def _scan_all(self) -> None:
        """Initial scan of all watch directories."""
        for watch_dir in self._watch_dirs:
            if not watch_dir.exists():
                continue

            for py_file in watch_dir.rglob("*.py"):
                if py_file.name.startswith("_"):
                    continue
                self._load_file(py_file)

    def _load_file(self, path: Path) -> Optional[ReloadEvent]:
        """Load a check module for the first time."""
        return self._reload_file(path, is_initial=True)

    def _reload_file(self, path: Path, is_initial: bool = False) -> ReloadEvent:
        """Reload a check module from disk.

        Args:
            path: Path to the Python file.
            is_initial: Whether this is the first load (not a reload).

        Returns:
            ReloadEvent describing the outcome.
        """
        start_time = time.time()
        file_key = str(path.resolve())
        module_name = path.stem

        try:
            # Read and hash the file content
            content = path.read_text()
            content_hash = hashlib.md5(content.encode()).hexdigest()

            # Skip if content unchanged (mtime updated but no real change)
            if file_key in self._modules:
                if self._modules[file_key].content_hash == content_hash:
                    return ReloadEvent(
                        timestamp=time.time(),
                        path=file_key,
                        module_name=module_name,
                        success=True,
                        checks_updated=[],
                        duration_ms=0.0,
                    )

            # Load or reload the module
            checks_found = self._execute_module_load(path, module_name, content)

            # Update tracking
            with self._lock:
                reload_count = 0
                if file_key in self._modules:
                    reload_count = self._modules[file_key].reload_count + 1

                self._modules[file_key] = CheckModule(
                    path=file_key,
                    module_name=module_name,
                    last_modified=path.stat().st_mtime,
                    content_hash=content_hash,
                    checks=checks_found,
                    reload_count=reload_count,
                )

            duration_ms = (time.time() - start_time) * 1000

            event = ReloadEvent(
                timestamp=time.time(),
                path=file_key,
                module_name=module_name,
                success=True,
                checks_updated=checks_found,
                duration_ms=duration_ms,
            )
            self._events.append(event)

            if self._on_reload and not is_initial:
                self._on_reload(event)

            return event

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000

            # Record the error but don't crash
            if file_key in self._modules:
                self._modules[file_key].load_error = str(e)

            event = ReloadEvent(
                timestamp=time.time(),
                path=file_key,
                module_name=module_name,
                success=False,
                checks_updated=[],
                error=str(e),
                duration_ms=duration_ms,
            )
            self._events.append(event)

            if self._on_error:
                self._on_error(event)

            return event

    def _execute_module_load(
        self, path: Path, module_name: str, content: str
    ) -> List[str]:
        """Execute the module load and extract check functions.

        Args:
            path: File path.
            module_name: Module name to use.
            content: File content (already read).

        Returns:
            List of check function names found.
        """
        # Create a unique module name to avoid conflicts
        full_module_name = f"guardrailgraph._hot_reload.{module_name}"

        # Load the module from the file path
        spec = importlib.util.spec_from_file_location(full_module_name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot create module spec for {path}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[full_module_name] = module
        spec.loader.exec_module(module)

        # Extract check functions (functions decorated with @check)
        checks_found: List[str] = []
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if callable(attr) and hasattr(attr, "_check_metadata"):
                check_name = getattr(attr, "_check_metadata", {}).get("name", attr_name)
                with self._lock:
                    self._check_registry[check_name] = attr
                checks_found.append(check_name)

        return checks_found

    def _compute_hash(self, content: str) -> str:
        """Compute content hash for change detection."""
        return hashlib.md5(content.encode()).hexdigest()
