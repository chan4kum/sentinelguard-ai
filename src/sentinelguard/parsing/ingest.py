"""Upload validation. Uploaded bytes are treated as untrusted DATA and never touch the filesystem."""

from __future__ import annotations

import re
from dataclasses import dataclass

from sentinelguard.domain.models import SourceFormat
from sentinelguard.errors import (
    FileTooLargeError,
    InvalidUploadError,
    UnsupportedFileTypeError,
)

ALLOWED_EXTENSIONS: dict[str, SourceFormat] = {
    ".tf": SourceFormat.TERRAFORM,
    ".json": SourceFormat.CLOUDFORMATION,
    ".yaml": SourceFormat.CLOUDFORMATION,
    ".yml": SourceFormat.CLOUDFORMATION,
    ".template": SourceFormat.CLOUDFORMATION,
}
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_MAX_NAME_LENGTH = 128


@dataclass(frozen=True)
class IacFile:
    """A validated upload: a safe display name, decoded text, and its detected format."""

    name: str
    text: str
    format: SourceFormat


def sanitize_filename(raw: str | None) -> str:
    """Reduce a client-supplied name to a harmless basename used only as a display label."""
    if not raw:
        raise InvalidUploadError("Every uploaded file must have a filename.")
    name = raw.replace("\\", "/").rsplit("/", 1)[-1]
    name = _CONTROL_CHARS.sub("", name).strip().strip(".")
    if not name:
        raise InvalidUploadError("Uploaded file has an invalid filename.")
    if len(name) > _MAX_NAME_LENGTH:
        # Truncate the stem but keep the extension so the file type is still recognised.
        dot = name.rfind(".")
        extension = name[dot:] if 0 < dot and len(name) - dot <= 16 else ""
        name = name[: _MAX_NAME_LENGTH - len(extension)] + extension
    return name


def validate_upload(raw_name: str | None, data: bytes, max_bytes: int) -> IacFile:
    name = sanitize_filename(raw_name)
    lowered = name.lower()
    extension = next((ext for ext in ALLOWED_EXTENSIONS if lowered.endswith(ext)), None)
    if extension is None:
        raise UnsupportedFileTypeError(
            f"Unsupported file type for '{name}'. Supported: "
            + ", ".join(sorted(ALLOWED_EXTENSIONS))
            + "."
        )
    if len(data) > max_bytes:
        raise FileTooLargeError(f"'{name}' exceeds the {max_bytes} byte limit.")
    if not data.strip():
        raise InvalidUploadError(f"'{name}' is empty.")
    if b"\x00" in data:
        raise InvalidUploadError(f"'{name}' contains binary data and is not a text IaC file.")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise InvalidUploadError(f"'{name}' is not valid UTF-8 text.") from None
    return IacFile(name=name, text=text, format=ALLOWED_EXTENSIONS[extension])
