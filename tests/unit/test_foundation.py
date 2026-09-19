from __future__ import annotations

import json
import logging

import pytest
from pydantic import ValidationError
from sqlalchemy import inspect

from sentinelguard import errors
from sentinelguard.config import Settings
from sentinelguard.logging_config import JsonFormatter, configure_logging, request_id_ctx
from sentinelguard.persistence.database import init_db, make_engine


def test_settings_defaults_are_safe_and_local():
    s = Settings()
    assert s.database_url.startswith("sqlite:///")
    assert s.max_upload_bytes == 1_048_576


def test_settings_read_environment(monkeypatch):
    monkeypatch.setenv("SENTINELGUARD_MAX_FILES_PER_SCAN", "4")
    monkeypatch.setenv("SENTINELGUARD_LOG_FORMAT", "text")
    s = Settings()
    assert s.max_files_per_scan == 4
    assert s.log_format == "text"


def test_settings_reject_absurd_limits(monkeypatch):
    monkeypatch.setenv("SENTINELGUARD_MAX_UPLOAD_BYTES", "999999999999")
    with pytest.raises(ValidationError):
        Settings()


def test_json_log_format_includes_context_and_extras():
    token = request_id_ctx.set("req-1")
    try:
        record = logging.LogRecord("x", logging.INFO, __file__, 1, "hello %s", ("w",), None)
        record.event = "demo"
        payload = json.loads(JsonFormatter().format(record))
    finally:
        request_id_ctx.reset(token)
    assert payload["message"] == "hello w"
    assert payload["level"] == "INFO"
    assert payload["request_id"] == "req-1"
    assert payload["event"] == "demo"


def test_configure_logging_is_idempotent(capsys):
    configure_logging("INFO", "json")
    configure_logging("INFO", "json")
    logging.getLogger("t").info("once")
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert len(lines) == 1
    assert json.loads(lines[0])["message"] == "once"


@pytest.mark.parametrize(
    ("exc", "status", "code"),
    [
        (errors.InvalidUploadError, 400, "invalid_upload"),
        (errors.NotFoundError, 404, "not_found"),
        (errors.FileTooLargeError, 413, "file_too_large"),
        (errors.UnsupportedFileTypeError, 415, "unsupported_file_type"),
        (errors.IaCParseError, 422, "parse_error"),
    ],
)
def test_error_types_map_to_http(exc, status, code):
    err = exc("msg", ["d"])
    assert (err.status_code, err.code, err.message, err.details) == (status, code, "msg", ["d"])


def test_init_db_creates_tables_and_is_idempotent(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'nested' / 'x.db'}")
    init_db(engine)
    init_db(engine)
    assert set(inspect(engine).get_table_names()) == {"scans", "findings"}


def test_in_memory_sqlite_supported():
    engine = make_engine("sqlite://")
    init_db(engine)
    assert "scans" in inspect(engine).get_table_names()
