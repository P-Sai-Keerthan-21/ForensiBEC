"""Regression: state and intelligence locations must not depend on the current
working directory. Found in the final audit: launched from outside the
repository, the local intelligence list was silently not found (the same email
lost a finding) and cases were created in a different output/ directory."""

from __future__ import annotations

from pathlib import Path

from bec_detector import config
from bec_detector.cases import CaseStore
from bec_detector.forensics import IOCStore, LocalThreatIntelProvider

ROOT = Path(__file__).resolve().parent.parent


def test_project_root_is_the_repository():
    assert config.PROJECT_ROOT == ROOT
    assert config.LOCAL_INTEL_FILE == ROOT / "data" / "local_intel.json"


def test_local_intel_found_from_any_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    provider = LocalThreatIntelProvider()
    assert provider.path.is_absolute()
    matches = provider.lookup({"domains": ["northwind-logistics.support"]})
    assert matches and matches[0].verdict == "known-bad"


def test_default_data_dir_is_anchored_to_project(tmp_path, monkeypatch):
    monkeypatch.delenv("FORENSIBEC_DATA_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    assert config.data_dir() == ROOT / "output"
    assert CaseStore().root == ROOT / "output" / "cases"
    assert IOCStore().path == ROOT / "output" / "ioc_store.json"


def test_data_dir_override_still_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIBEC_DATA_DIR", str(tmp_path))
    assert config.data_dir() == tmp_path
    assert CaseStore().root == tmp_path / "cases"


def test_reports_do_not_disclose_the_install_location():
    """Anchoring paths to the project must not put absolute paths (install
    location, Windows user name) into reports or the API."""
    provider = LocalThreatIntelProvider()
    assert str(ROOT) not in provider.status()
    assert "local_intel.json" in provider.status()
    assert config.display_path(ROOT / "output" / "ioc_store.json") == str(
        Path("output") / "ioc_store.json")


def test_display_path_outside_project_is_unchanged(tmp_path):
    assert config.display_path(tmp_path / "x.json") == str(tmp_path / "x.json")
