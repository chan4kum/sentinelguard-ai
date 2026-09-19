"""HTTP client for the SentinelGuard API. The dashboard talks to the API only through this."""

from __future__ import annotations

from typing import Any

import httpx


class ApiError(Exception):
    """Raised with a message that is safe to display to the dashboard user."""


class ApiClient:
    def __init__(self, base_url: str, timeout: float = 30.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    @property
    def base_url(self) -> str:
        return self._base_url

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = httpx.request(
                method, f"{self._base_url}{path}", timeout=self._timeout, **kwargs
            )
        except httpx.HTTPError:
            raise ApiError(
                f"Cannot reach the SentinelGuard API at {self._base_url}. Is it running?"
            ) from None
        if response.status_code >= 400:
            try:
                message = response.json()["error"]["message"]
            except (ValueError, KeyError, TypeError):
                message = f"API returned HTTP {response.status_code}."
            raise ApiError(message)
        return response.json()

    def summary(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/dashboard/summary")

    def list_scans(self, limit: int = 25) -> list[dict[str, Any]]:
        return self._request("GET", "/api/v1/scans", params={"limit": limit})["items"]

    def get_scan(self, scan_id: str) -> dict[str, Any]:
        return self._request("GET", f"/api/v1/scans/{scan_id}")

    def upload_scan(self, files: list[tuple[str, bytes]]) -> dict[str, Any]:
        payload = [("files", (name, data, "application/octet-stream")) for name, data in files]
        return self._request("POST", "/api/v1/scans", files=payload)
