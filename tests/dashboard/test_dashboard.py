"""Dashboard verification: the real Streamlit script runs against a real, live API."""

from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from sentinelguard.dashboard import app as dashboard_app
from sentinelguard.dashboard.client import ApiClient, ApiError

APP_PATH = str(Path(dashboard_app.__file__))

pytestmark = pytest.mark.integration


def seed(base_url: str, samples: Path, *relatives: str) -> list[dict]:
    client = ApiClient(base_url)
    return [
        client.upload_scan([((samples / r).name, (samples / r).read_bytes())]) for r in relatives
    ]


def run_app(base_url: str, monkeypatch) -> AppTest:
    monkeypatch.setenv("SENTINELGUARD_API_BASE_URL", base_url)
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    return at


def metrics(at: AppTest) -> dict[str, str]:
    return {m.label: m.value for m in at.metric}


# --------------------------------------------------------------------------- client


def test_client_roundtrip_against_live_api(live_api, samples):
    client = ApiClient(live_api)
    assert client.summary()["scan_count"] == 0
    scan = client.upload_scan(
        [("vulnerable.tf", (samples / "terraform/vulnerable.tf").read_bytes())]
    )
    assert scan["risk_score"] == 100
    assert client.summary()["scan_count"] == 1
    assert client.list_scans()[0]["scan_id"] == scan["scan_id"]
    assert len(client.get_scan(scan["scan_id"])["findings"]) == 10


def test_client_maps_api_errors_to_safe_messages(live_api):
    client = ApiClient(live_api)
    with pytest.raises(ApiError, match="Unsupported file type"):
        client.upload_scan([("evil.exe", b"MZ")])
    with pytest.raises(ApiError, match="Scan not found"):
        client.get_scan("missing")


def test_client_reports_unreachable_api():
    with pytest.raises(ApiError, match="Cannot reach the SentinelGuard API"):
        ApiClient("http://127.0.0.1:1", timeout=2).summary()


# ----------------------------------------------------------------------- dashboard


def test_dashboard_empty_state(live_api, monkeypatch):
    at = run_app(live_api, monkeypatch)
    assert not at.exception
    assert at.title[0].value == "🛡️ SentinelGuard AI"
    assert at.caption[0].value == "Enterprise Security Guardrail Auditor"
    m = metrics(at)
    assert m["Overall Risk Score"] == "0 / 100" and m["Scans"] == "0"
    assert m["Total findings"] == "0" and m["Risk classification"] == "SECURE"
    assert any("No scans yet" in i.value for i in at.info)


def test_dashboard_shows_scores_counts_and_classification(live_api, samples, monkeypatch):
    seed(live_api, samples, "terraform/vulnerable.tf", "azure/vulnerable.tf", "terraform/safe.tf")
    at = run_app(live_api, monkeypatch)
    assert not at.exception
    m = metrics(at)
    assert m["Overall Risk Score"] == "67 / 100"  # mean(100, 100, 0)
    assert m["Risk classification"] == "HIGH"
    assert m["Scans"] == "3" and m["Total findings"] == "14"
    assert (m["Critical"], m["High"], m["Medium"], m["Low"]) == ("6", "5", "3", "0")
    subheaders = [s.value for s in at.subheader]
    for expected in (
        "Findings by severity",
        "Findings by cloud provider",
        "Findings by rule",
        "Recent scans",
        "Scan details",
    ):
        assert expected in subheaders


def test_dashboard_recent_scans_table_lists_scans(live_api, samples, monkeypatch):
    scans = seed(live_api, samples, "terraform/safe.tf", "terraform/vulnerable.tf")
    at = run_app(live_api, monkeypatch)
    table = at.dataframe[0].value
    assert list(table.columns) == ["Scan", "When (UTC)", "Files", "Risk score", "Level", "Findings"]
    assert table["Scan"].tolist() == [s["scan_id"][:8] for s in reversed(scans)]  # newest first
    assert table["Risk score"].tolist() == [100, 0]
    assert table["Findings"].tolist() == [10, 0]


def test_dashboard_finding_details_evidence_and_remediation(live_api, samples, monkeypatch):
    seed(live_api, samples, "terraform/vulnerable.tf")
    at = run_app(live_api, monkeypatch)
    labels = [e.label for e in at.expander]
    assert len(labels) == 10
    assert labels[0].startswith("🔴 CRITICAL · AWS-")
    ssh = next(e for e in at.expander if "AWS-EC2-001" in e.label)
    rendered = " ".join(str(c.value) for c in ssh.code) + " ".join(str(i.value) for i in ssh.info)
    assert "aws_security_group.bastion" in rendered
    assert "0.0.0.0/0" in rendered and "port 22" in rendered
    assert "Session Manager" in rendered  # remediation text
    assert any("Why this score?" in md.value for md in at.markdown)
    text = " ".join(md.value for md in at.markdown)
    assert "capped at 100" in text and "band **critical**" in text


def test_dashboard_explains_escalation(live_api, monkeypatch):
    tf = (
        b'resource "aws_security_group" "s" {\n  ingress {\n    from_port = 22\n    to_port = 22\n'
        b'    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
    )
    ApiClient(live_api).upload_scan([("ssh.tf", tf)])
    at = run_app(live_api, monkeypatch)
    text = " ".join(md.value for md in at.markdown)
    assert "raised to **high** because a CRITICAL finding is present" in text


def test_dashboard_zero_finding_scan_shows_success(live_api, samples, monkeypatch):
    seed(live_api, samples, "cloudformation/safe.yaml")
    at = run_app(live_api, monkeypatch)
    assert not at.exception
    assert any("No guardrail violations" in s.value for s in at.success)
    assert metrics(at)["Overall Risk Score"] == "0 / 100"


def test_dashboard_scan_selector_switches_detail(live_api, samples, monkeypatch):
    seed(live_api, samples, "terraform/vulnerable.tf", "terraform/safe.tf")  # safe is newest
    at = run_app(live_api, monkeypatch)
    # default: newest scan WITH findings, not the (newer) clean one
    assert "vulnerable.tf" in at.selectbox[0].value
    assert len(at.expander) == 10

    selector = at.selectbox[0]
    safe_label = next(o for o in selector.options if "safe.tf" in o)
    selector.select(safe_label).run()
    assert not at.exception
    assert len(at.expander) == 0
    assert any("No guardrail violations" in s.value for s in at.success)


def test_dashboard_shows_friendly_error_when_api_is_down(monkeypatch):
    at = run_app("http://127.0.0.1:1", monkeypatch)
    assert not at.exception
    assert any("Cannot reach the SentinelGuard API" in e.value for e in at.error)


def test_dashboard_renders_hostile_resource_names_as_text(live_api, monkeypatch):
    """Resource names come from uploaded files: they must never be rendered as HTML."""
    evil = b'resource "aws_ebs_volume" "<img src=x onerror=alert(1)>" {\n  size = 1\n}\n'
    ApiClient(live_api).upload_scan([("evil.tf", evil)])
    at = run_app(live_api, monkeypatch)
    assert not at.exception
    for md in at.markdown:
        assert "<img" not in md.value
