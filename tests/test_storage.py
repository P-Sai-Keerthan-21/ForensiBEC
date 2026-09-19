"""Regression: persisted state is written atomically and each case is locked
across processes. Found in the final audit - the audit hash chain was built by
read-previous-hash-then-append with no lock, so the CLI and the server acting
on one case at the same moment could fork the chain (the case would then fail
verification permanently), and case.json / the IOC store were rewritten in
place, so a crash mid-write left a truncated file."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bec_detector import storage
from bec_detector.cases import CaseError, CaseStore
from bec_detector.forensics import IOCStore

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


def test_atomic_write_replaces_whole_file_and_leaves_no_temp(tmp_path):
    target = tmp_path / "state.json"
    storage.atomic_write_text(target, "old")
    storage.atomic_write_text(target, "new content")
    assert target.read_text(encoding="utf-8") == "new content"
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]


def test_lock_is_reentrant_within_a_process(tmp_path):
    lock = tmp_path / ".lock"
    with storage.locked(lock):
        with storage.locked(lock):
            pass
    with storage.locked(lock, timeout=1):  # released afterwards
        pass


def test_case_held_by_another_process_is_reported_busy(tmp_path, monkeypatch):
    """A second OS-level handle on the lock file stands in for another process:
    the case must refuse with a clear error, not write or hang."""
    store = CaseStore(tmp_path / "cases")
    store.create("CASE-LOCK")
    monkeypatch.setattr(storage, "LOCK_TIMEOUT_S", 0.3)
    lock_file = store._dir("CASE-LOCK") / ".lock"
    with open(lock_file, "a+b") as other:
        assert storage._try_lock(other)
        try:
            with pytest.raises(CaseError, match="busy in another process"):
                store.add_evidence("CASE-LOCK", (SAMPLES / "ben_01_internal_meeting.eml").read_bytes(), "a.eml")
        finally:
            storage._unlock(other)
    assert store.load("CASE-LOCK").evidence == []
    store.add_evidence("CASE-LOCK", (SAMPLES / "ben_01_internal_meeting.eml").read_bytes(), "a.eml")
    assert store.verify("CASE-LOCK")["intact"]


def test_missing_case_does_not_leave_a_directory(tmp_path):
    store = CaseStore(tmp_path / "cases")
    with pytest.raises(CaseError):
        store.add_evidence("CASE-NOPE", b"x", "x.eml")
    assert not (tmp_path / "cases" / "CASE-NOPE").exists()


def test_ioc_store_save_merges_with_concurrent_writer(tmp_path):
    """Two processes each loaded the store, recorded different cases, then saved."""
    path = tmp_path / "ioc.json"
    a, b = IOCStore(path), IOCStore(path)
    a.record({"domains": ["evil-one.example"], "ipv4": ["203.0.113.9"]}, "CASE-A")
    b.record({"domains": ["evil-two.example"], "ipv4": ["203.0.113.9"]}, "CASE-B")
    a.save()
    b.save()
    merged = json.loads(path.read_text(encoding="utf-8"))
    assert set(merged["domains"]) == {"evil-one.example", "evil-two.example"}
    assert merged["ipv4"]["203.0.113.9"]["cases"] == ["CASE-A", "CASE-B"]


def test_truncated_ioc_store_is_not_produced_by_save(tmp_path):
    path = tmp_path / "ioc.json"
    store = IOCStore(path)
    store.record({"domains": ["x.example"]}, "CASE-A")
    store.save()
    json.loads(path.read_text(encoding="utf-8"))  # always complete JSON


def test_two_audit_writers_on_one_file_never_fork_the_chain(tmp_path):
    """Two AuditLog objects on one file stand in for two processes (e.g. two
    `scan --audit same.jsonl` runs). Each was loaded before the other wrote;
    each append must still chain from the true head."""
    from bec_detector.forensics import AuditLog

    path = tmp_path / "audit.jsonl"
    first, second = AuditLog(path, actor="a"), AuditLog(path, actor="b")
    for i in range(3):
        first.record("step", f"a{i}")
        second.record("step", f"b{i}")
    result = AuditLog(path).verify()
    assert result["valid"], result
    assert result["entries"] == 6
