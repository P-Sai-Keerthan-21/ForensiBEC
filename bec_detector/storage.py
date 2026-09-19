"""Crash- and concurrency-safe primitives for persisted state.

Two processes (for example the CLI and the web server) can act on the same
case. Without coordination, two appends to a hash-chained audit log can both
read the same predecessor hash, forking the chain so the case fails
verification permanently; and a crash part-way through rewriting case.json or
the IOC store leaves a truncated file.

* `locked(path)` - an exclusive, cross-process lock on `path`, held with the
  operating system's file locking (msvcrt on Windows, fcntl elsewhere). The OS
  releases it if the process dies, so a lock can never go stale. Re-entrant
  within a process.
* `atomic_write_text(path, text)` - write to a temporary file in the same
  directory, flush it to disk, then replace the target in one step. Readers
  see the old file or the new one, never a partial one.
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

LOCK_TIMEOUT_S = 120.0

_held: dict[str, int] = {}
_thread_locks: dict[str, threading.RLock] = {}
_registry = threading.Lock()


class StateBusy(RuntimeError):
    """Another process held the lock for longer than LOCK_TIMEOUT_S."""


def _try_lock(fh) -> bool:
    try:
        if os.name == "nt":
            import msvcrt
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def _unlock(fh) -> None:
    try:
        if os.name == "nt":
            import msvcrt
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass


@contextmanager
def locked(lock_path: str | Path, timeout: float | None = None) -> Iterator[None]:
    """Hold an exclusive lock on `lock_path` (created if missing)."""
    if timeout is None:
        timeout = LOCK_TIMEOUT_S
    lock_path = Path(lock_path)
    key = str(lock_path.resolve())
    with _registry:
        thread_lock = _thread_locks.setdefault(key, threading.RLock())
    with thread_lock:
        if _held.get(key):
            _held[key] += 1
            try:
                yield
            finally:
                _held[key] -= 1
            return
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(lock_path, "a+b")
        try:
            deadline = time.monotonic() + timeout
            while not _try_lock(fh):
                if time.monotonic() > deadline:
                    raise StateBusy(f"{lock_path.parent.name} is busy in another process.")
                time.sleep(0.05)
            _held[key] = 1
            try:
                yield
            finally:
                _held[key] = 0
                _unlock(fh)
        finally:
            fh.close()


def atomic_write_text(path: str | Path, text: str) -> None:
    """Replace `path` with `text` in one step (UTF-8)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        # Windows refuses to replace a file another process has open for a
        # moment (a concurrent reader); retry briefly rather than fail.
        for attempt in range(50):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if attempt == 49:
                    raise
                time.sleep(0.02)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
