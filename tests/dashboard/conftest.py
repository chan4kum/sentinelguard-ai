from __future__ import annotations

import socket
import threading
import time

import pytest
import uvicorn

from sentinelguard.api.app import create_app
from sentinelguard.config import Settings


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live_api(tmp_path):
    """A REAL uvicorn server on a temp SQLite database (no TestClient, no mocks)."""
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'live.db'}", log_format="text", log_level="WARNING"
    )
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(create_app(settings), host="127.0.0.1", port=port, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while not server.started:
        if time.time() > deadline:
            raise RuntimeError("live API failed to start")
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=10)
