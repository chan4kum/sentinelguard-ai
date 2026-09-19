from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinelguard.api.app import create_app
from sentinelguard.config import Settings

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        log_format="text",
        log_level="WARNING",
        max_upload_bytes=64 * 1024,
        max_files_per_scan=3,
    )


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture
def samples() -> Path:
    return SAMPLES
