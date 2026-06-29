"""Tests for custom check hot-reload without pipeline restart."""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

import pytest

from guardrailgraph.pipeline.hot_reload import (
    CheckModule,
    HotReloader,
    ReloadEvent,
)


def _write_check_file(dir_path: Path, name: str, content: str) -> Path:
    """Helper to write a check file."""
    file_path = dir_path / f"{name}.py"
    file_path.write_text(content)
    return file_path


SIMPLE_CHECK = '''
from guardrailgraph.core.check import check
from guardrailgraph.core.actions import Action

@check(name="test-check", action=Action.BLOCK, threshold=0.5)
def test_check(text: str) -> dict:
    return {"detected": "bad" in text.lower(), "confidence": 0.9}
'''

UPDATED_CHECK = '''
from guardrailgraph.core.check import check
from guardrailgraph.core.actions import Action

@check(name="test-check", action=Action.BLOCK, threshold=0.8)
def test_check(text: str) -> dict:
    return {"detected": "evil" in text.lower(), "confidence": 0.95}
'''


class TestHotReloaderInit:
    """Test initialization behavior."""

    def test_default_configuration(self):
        reloader = HotReloader(watch_dirs=["/nonexistent"])
        assert reloader.is_running is False
        assert reloader.watched_modules == {}
        assert reloader.events == []

    def test_initial_scan_loads_existing_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_check_file(Path(tmp), "my_check", SIMPLE_CHECK)
            reloader = HotReloader(watch_dirs=[tmp])
            # Should have loaded the file
            assert len(reloader.watched_modules) == 1

    def test_skips_underscore_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_check_file(Path(tmp), "_private", SIMPLE_CHECK)
            _write_check_file(Path(tmp), "__init__", "")
            reloader = HotReloader(watch_dirs=[tmp])
            assert len(reloader.watched_modules) == 0

    def test_handles_nonexistent_directory(self):
        reloader = HotReloader(watch_dirs=["/does/not/exist"])
        assert len(reloader.watched_modules) == 0


class TestModuleLoading:
    """Test module load and reload behavior."""

    def test_load_extracts_check_functions(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_check_file(Path(tmp), "profanity", SIMPLE_CHECK)
            reloader = HotReloader(watch_dirs=[tmp])
            modules = reloader.watched_modules
            assert len(modules) == 1
            module = list(modules.values())[0]
            assert "test-check" in module.checks

    def test_reload_updates_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            file_path = _write_check_file(Path(tmp), "evolving", SIMPLE_CHECK)
            reloader = HotReloader(watch_dirs=[tmp])

            # Modify the file
            time.sleep(0.01)
            file_path.write_text(UPDATED_CHECK)

            # Force reload
            event = reloader.reload_module(str(file_path))
            assert event.success is True
            assert "test-check" in event.checks_updated

    def test_reload_increments_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            file_path = _write_check_file(Path(tmp), "counter", SIMPLE_CHECK)
            reloader = HotReloader(watch_dirs=[tmp])

            # Reload multiple times
            file_path.write_text(UPDATED_CHECK)
            reloader.reload_module(str(file_path))

            file_path.write_text(SIMPLE_CHECK)
            reloader.reload_module(str(file_path))

            module = list(reloader.watched_modules.values())[0]
            assert module.reload_count >= 2

    def test_reload_with_syntax_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            file_path = _write_check_file(Path(tmp), "broken", SIMPLE_CHECK)
            reloader = HotReloader(watch_dirs=[tmp])

            # Write invalid Python
            file_path.write_text("def broken(:\n  pass")
            event = reloader.reload_module(str(file_path))
            assert event.success is False
            assert event.error is not None

    def test_unchanged_content_skips_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            file_path = _write_check_file(Path(tmp), "stable", SIMPLE_CHECK)
            reloader = HotReloader(watch_dirs=[tmp])

            # Touch the file (mtime changes but content same)
            file_path.write_text(SIMPLE_CHECK)
            event = reloader.reload_module(str(file_path))
            assert event.success is True
            assert event.checks_updated == []  # No actual changes


class TestCheckRegistry:
    """Test the check function registry."""

    def test_get_check_by_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_check_file(Path(tmp), "my_check", SIMPLE_CHECK)
            reloader = HotReloader(watch_dirs=[tmp])
            check_fn = reloader.get_check("test-check")
            assert check_fn is not None
            assert callable(check_fn)

    def test_get_nonexistent_check(self):
        reloader = HotReloader(watch_dirs=["/nonexistent"])
        assert reloader.get_check("does-not-exist") is None

    def test_registry_updates_on_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            file_path = _write_check_file(Path(tmp), "updatable", SIMPLE_CHECK)
            reloader = HotReloader(watch_dirs=[tmp])

            # Get initial version
            check_v1 = reloader.get_check("test-check")
            assert check_v1 is not None

            # Update and reload
            file_path.write_text(UPDATED_CHECK)
            reloader.reload_module(str(file_path))

            check_v2 = reloader.get_check("test-check")
            assert check_v2 is not None
            # The function should be different (reloaded)


class TestWatcherLifecycle:
    """Test start/stop behavior."""

    def test_start_and_stop(self):
        reloader = HotReloader(watch_dirs=["/nonexistent"], poll_interval=0.1)
        reloader.start()
        assert reloader.is_running is True
        reloader.stop()
        assert reloader.is_running is False

    def test_auto_start(self):
        reloader = HotReloader(
            watch_dirs=["/nonexistent"],
            poll_interval=0.1,
            auto_start=True,
        )
        assert reloader.is_running is True
        reloader.stop()

    def test_double_start_is_safe(self):
        reloader = HotReloader(watch_dirs=["/nonexistent"], poll_interval=0.1)
        reloader.start()
        reloader.start()  # Should not crash
        assert reloader.is_running is True
        reloader.stop()


class TestCallbacks:
    """Test reload and error callbacks."""

    def test_on_reload_callback(self):
        events_received = []

        with tempfile.TemporaryDirectory() as tmp:
            file_path = _write_check_file(Path(tmp), "cb_test", SIMPLE_CHECK)
            reloader = HotReloader(
                watch_dirs=[tmp],
                on_reload=lambda e: events_received.append(e),
            )

            # Trigger reload
            file_path.write_text(UPDATED_CHECK)
            reloader.reload_module(str(file_path))

            assert len(events_received) == 1
            assert events_received[0].success is True

    def test_on_error_callback(self):
        errors_received = []

        with tempfile.TemporaryDirectory() as tmp:
            file_path = _write_check_file(Path(tmp), "err_test", SIMPLE_CHECK)
            reloader = HotReloader(
                watch_dirs=[tmp],
                on_error=lambda e: errors_received.append(e),
            )

            # Write broken code
            file_path.write_text("this is not valid python {{{{")
            reloader.reload_module(str(file_path))

            assert len(errors_received) == 1
            assert errors_received[0].success is False


class TestReloadEvent:
    """Test ReloadEvent dataclass."""

    def test_event_fields(self):
        event = ReloadEvent(
            timestamp=time.time(),
            path="/tmp/check.py",
            module_name="check",
            success=True,
            checks_updated=["my-check"],
            duration_ms=12.5,
        )
        assert event.success is True
        assert event.module_name == "check"
        assert event.duration_ms == 12.5
        assert event.error is None
