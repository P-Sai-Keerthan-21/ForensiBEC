"""Shared test configuration.

Every test session gets a private, throwaway data directory. Case stores, the
IOC correlation store and per-case audit logs are written there instead of to
output/, so tests can never pollute an investigator's real case data - and no
test result can depend on what earlier runs left behind.
"""

from __future__ import annotations

import os

import pytest

# The web app only serves known local host names (DNS-rebinding defence).
# The test client addresses requests to "testserver", so allow it - set at
# import time, before any test module imports the app.
os.environ.setdefault("FORENSIBEC_ALLOWED_HOSTS", "127.0.0.1,localhost,testserver")


@pytest.fixture(scope="session", autouse=True)
def isolated_data_dir(tmp_path_factory):
    path = tmp_path_factory.mktemp("forensibec-data")
    previous = os.environ.get("FORENSIBEC_DATA_DIR")
    os.environ["FORENSIBEC_DATA_DIR"] = str(path)
    yield path
    if previous is None:
        os.environ.pop("FORENSIBEC_DATA_DIR", None)
    else:
        os.environ["FORENSIBEC_DATA_DIR"] = previous
