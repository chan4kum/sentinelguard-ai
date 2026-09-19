"""Scan every bundled sample through the running API so the dashboard has data.

Usage:  python scripts/seed_demo.py [API_BASE_URL]
"""

from __future__ import annotations

import sys
from pathlib import Path

from sentinelguard.dashboard.client import ApiClient, ApiError

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def main() -> int:
    client = ApiClient(sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000")
    for path in sorted(p for p in SAMPLES.rglob("*") if p.is_file()):
        try:
            scan = client.upload_scan([(path.name, path.read_bytes())])
        except ApiError as exc:
            print(f"FAILED  {path.relative_to(SAMPLES)}: {exc}")
            return 1
        print(
            f"{path.relative_to(SAMPLES)!s:38} risk={scan['risk_score']:>3} "
            f"level={scan['risk_level']:<8} findings={scan['finding_count']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
