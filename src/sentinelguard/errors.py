"""Typed application errors. Messages are safe to show to API clients."""

from __future__ import annotations


class SentinelError(Exception):
    status_code = 500
    code = "internal_error"

    def __init__(self, message: str, details: list[str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class InvalidUploadError(SentinelError):
    status_code = 400
    code = "invalid_upload"


class NotFoundError(SentinelError):
    status_code = 404
    code = "not_found"


class FileTooLargeError(SentinelError):
    status_code = 413
    code = "file_too_large"


class UnsupportedFileTypeError(SentinelError):
    status_code = 415
    code = "unsupported_file_type"


class IaCParseError(SentinelError):
    status_code = 422
    code = "parse_error"
