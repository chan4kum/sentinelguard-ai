from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from sentinelguard.api.app import create_app


def upload(client, *files: tuple[str, bytes], path: str = "/api/v1/scans"):
    payload = [("files", (name, data, "application/octet-stream")) for name, data in files]
    return client.post(path, files=payload)


def scan_sample(client, samples, relative: str):
    path = samples / relative
    return upload(client, (path.name, path.read_bytes()))


# ------------------------------------------------------------------- happy paths


def test_scan_vulnerable_terraform(client, samples):
    r = scan_sample(client, samples, "terraform/vulnerable.tf")
    assert r.status_code == 201
    body = r.json()
    assert body["finding_count"] == 10 == len(body["findings"])
    assert body["risk_score"] == 100 and body["risk_level"] == "critical"
    assert body["files"] == ["vulnerable.tf"] and body["formats"] == ["terraform"]
    assert body["resources_total"] == 9 and body["resources_analyzed"] == 9
    assert body["severity_counts"] == {"critical": 4, "high": 3, "medium": 3, "low": 0}
    breakdown = body["score_breakdown"]
    assert breakdown["raw_total"] == 210 and breakdown["cap_applied"] is True
    assert sum(c["points"] for c in breakdown["contributions"]) == 210
    first = body["findings"][0]
    assert first["severity"] == "critical"
    for key in (
        "finding_id", "scan_id", "rule_id", "provider", "resource_type", "resource_name",
        "severity", "description", "evidence", "remediation", "risk_weight", "title", "source_file",
    ):  # fmt: skip
        assert key in first and first[key] not in (None, "", [])
    assert first["scan_id"] == body["scan_id"]


def test_scan_safe_terraform_is_zero_findings(client, samples):
    body = scan_sample(client, samples, "terraform/safe.tf").json()
    assert body["finding_count"] == 0 and body["findings"] == []
    assert body["risk_score"] == 0 and body["risk_level"] == "secure"
    assert body["score_breakdown"]["contributions"] == []


@pytest.mark.parametrize(
    ("relative", "findings", "score", "level"),
    [
        ("cloudformation/vulnerable.json", 8, 100, "critical"),
        ("cloudformation/vulnerable.yaml", 3, 70, "critical"),
        ("azure/vulnerable.tf", 4, 100, "critical"),
        ("cloudformation/safe.json", 0, 0, "secure"),
        ("cloudformation/safe.yaml", 0, 0, "secure"),
        ("azure/safe.tf", 0, 0, "secure"),
    ],
)
def test_scan_other_samples(client, samples, relative, findings, score, level):
    body = scan_sample(client, samples, relative).json()
    assert (body["finding_count"], body["risk_score"], body["risk_level"]) == (
        findings,
        score,
        level,
    )


def test_single_critical_finding_is_escalated_to_high(client):
    tf = b'resource "aws_security_group" "s" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
    body = upload(client, ("a.tf", tf)).json()
    assert body["risk_score"] == 30 and body["risk_level"] == "high"
    assert body["score_breakdown"]["escalated"] is True
    assert body["score_breakdown"]["score_band"] == "medium"


def test_multiple_files_in_one_scan_are_linked_and_mixed_formats(client):
    bucket = b'resource "aws_s3_bucket" "b" {\n  bucket = "n"\n}\n'
    pab = (
        b'resource "aws_s3_bucket_public_access_block" "p" {\n  bucket = aws_s3_bucket.b.id\n'
        b"  block_public_acls = true\n  block_public_policy = true\n  ignore_public_acls = true\n"
        b"  restrict_public_buckets = true\n}\n"
    )
    cfn = b'{"Resources": {"V": {"Type": "AWS::EC2::Volume", "Properties": {"Encrypted": false}}}}'
    body = upload(client, ("main.tf", bucket), ("pab.tf", pab), ("stack.json", cfn)).json()
    rules = sorted(f["rule_id"] for f in body["findings"])
    assert rules == ["AWS-ENC-001", "AWS-S3-003"]  # PAB in another file was linked (no S3-002)
    assert body["formats"] == ["terraform", "cloudformation"]
    assert body["files"] == ["main.tf", "pab.tf", "stack.json"]


def test_scan_with_only_unsupported_resources_is_a_clean_zero(client):
    body = upload(client, ("a.tf", b'resource "aws_instance" "x" {\n  ami = "a"\n}\n')).json()
    assert body["resources_total"] == 1 and body["resources_analyzed"] == 0
    assert body["risk_score"] == 0


# --------------------------------------------------------------- retrieval / persistence


def test_get_scan_matches_created_scan(client, samples):
    created = scan_sample(client, samples, "terraform/vulnerable.tf").json()
    fetched = client.get(f"/api/v1/scans/{created['scan_id']}")
    assert fetched.status_code == 200
    assert fetched.json() == created


def test_list_scans_newest_first_with_paging(client, samples):
    ids = [scan_sample(client, samples, "terraform/safe.tf").json()["scan_id"] for _ in range(3)]
    page = client.get("/api/v1/scans?limit=2").json()
    assert page["total"] == 3 and page["limit"] == 2 and page["offset"] == 0
    assert [s["scan_id"] for s in page["items"]] == ids[::-1][:2]
    rest = client.get("/api/v1/scans?limit=2&offset=2").json()
    assert [s["scan_id"] for s in rest["items"]] == [ids[0]]
    assert "findings" not in page["items"][0]  # list view is lightweight


def test_list_scans_empty(client):
    assert client.get("/api/v1/scans").json() == {"items": [], "total": 0, "limit": 20, "offset": 0}


def test_findings_endpoint_orders_and_filters(client, samples):
    scan_id = scan_sample(client, samples, "terraform/vulnerable.tf").json()["scan_id"]
    everything = client.get(f"/api/v1/scans/{scan_id}/findings").json()
    assert len(everything) == 10
    order = ["critical", "high", "medium", "low"]
    assert [order.index(f["severity"]) for f in everything] == sorted(
        order.index(f["severity"]) for f in everything
    )
    high = client.get(f"/api/v1/scans/{scan_id}/findings?severity=high").json()
    assert {f["rule_id"] for f in high} == {"AWS-S3-002", "AWS-EC2-003", "AWS-RDS-001"}
    assert client.get(f"/api/v1/scans/{scan_id}/findings?severity=low").json() == []


def test_persistence_survives_application_restart(settings, samples):
    with TestClient(create_app(settings)) as first:
        created = scan_sample(first, samples, "terraform/vulnerable.tf").json()
    with TestClient(create_app(settings)) as second:  # new engine, same SQLite file
        assert second.get(f"/api/v1/scans/{created['scan_id']}").json() == created
        assert second.get("/api/v1/dashboard/summary").json()["scan_count"] == 1


def test_concurrent_scans_are_all_persisted(client, samples):
    data = (samples / "terraform" / "vulnerable.tf").read_bytes()

    def one(_):
        return upload(client, ("vulnerable.tf", data))

    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(one, range(8)))
    assert all(r.status_code == 201 for r in responses)
    ids = {r.json()["scan_id"] for r in responses}
    assert len(ids) == 8
    assert client.get("/api/v1/scans?limit=100").json()["total"] == 8
    assert client.get("/api/v1/dashboard/summary").json()["finding_count"] == 80


# --------------------------------------------------------------------- rules catalogue


def test_rules_endpoint_lists_the_baseline(client):
    r = client.get("/api/v1/rules")
    assert r.status_code == 200
    rules = r.json()
    assert len(rules) == 10 and len({x["rule_id"] for x in rules}) == 10
    for rule in rules:
        for key in (
            "rule_id", "title", "provider", "resource_kinds", "description",
            "detection", "severity", "risk_weight", "remediation",
        ):  # fmt: skip
            assert rule[key] not in (None, "", [])
    assert {x["provider"] for x in rules} == {"aws", "azure"}


# ------------------------------------------------------------------ dashboard summary


def test_dashboard_summary_empty(client):
    body = client.get("/api/v1/dashboard/summary").json()
    assert body["scan_count"] == 0 and body["finding_count"] == 0
    assert body["overall_risk_score"] == 0 and body["overall_risk_level"] == "secure"
    assert body["latest_scan_score"] is None and body["recent_scans"] == []
    assert body["findings_by_severity"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert "No scans yet" in body["score_explanation"]


def test_dashboard_summary_aggregates(client, samples):
    scan_sample(client, samples, "terraform/vulnerable.tf")  # 100, 10 findings (aws)
    scan_sample(client, samples, "azure/vulnerable.tf")  # 100, 4 findings (azure)
    scan_sample(client, samples, "terraform/safe.tf")  # 0
    body = client.get("/api/v1/dashboard/summary").json()
    assert body["scan_count"] == 3 and body["finding_count"] == 14
    assert body["overall_risk_score"] == 67 and body["overall_risk_level"] == "high"
    assert body["latest_scan_score"] == 0 and body["highest_scan_score"] == 100
    assert body["findings_by_severity"] == {"critical": 6, "high": 5, "medium": 3, "low": 0}
    assert body["findings_by_provider"] == {"aws": 10, "azure": 4}
    by_rule = {r["rule_id"]: r["count"] for r in body["findings_by_rule"]}
    assert by_rule["AWS-S3-001"] == 2 and by_rule["AZ-NSG-001"] == 2 and by_rule["AWS-ENC-001"] == 2
    counts = [r["count"] for r in body["findings_by_rule"]]
    assert counts == sorted(counts, reverse=True)
    assert len(body["recent_scans"]) == 3 and body["recent_scans"][0]["risk_score"] == 0
    assert "average of 3 scan" in body["score_explanation"]


def test_dashboard_recent_scans_capped_at_five(client, samples):
    for _ in range(7):
        scan_sample(client, samples, "terraform/safe.tf")
    assert len(client.get("/api/v1/dashboard/summary").json()["recent_scans"]) == 5


# ---------------------------------------------------------- validation & error handling


def assert_error(response, status: int, code: str):
    assert response.status_code == status, response.text
    error = response.json()["error"]
    assert error["code"] == code and error["message"] and error["request_id"]
    text = response.text
    assert "Traceback" not in text and "/Users/" not in text and "site-packages" not in text
    return error


def test_unknown_scan_is_404(client):
    assert_error(client.get("/api/v1/scans/does-not-exist"), 404, "not_found")
    assert_error(client.get("/api/v1/scans/does-not-exist/findings"), 404, "not_found")


def test_missing_files_field_is_validation_error(client):
    error = assert_error(client.post("/api/v1/scans"), 422, "validation_error")
    assert any("files" in d for d in error["details"])


def test_unsupported_extension_is_415(client):
    error = assert_error(upload(client, ("malware.exe", b"MZ")), 415, "unsupported_file_type")
    assert "malware.exe" in error["message"]


def test_oversize_file_is_413(client):
    assert_error(upload(client, ("big.tf", b"#" * (64 * 1024 + 1))), 413, "file_too_large")


def test_oversize_request_body_rejected_early_with_413(client):
    big = b"#" * (600 * 1024)
    assert_error(upload(client, ("big.tf", big)), 413, "file_too_large")


def test_empty_file_is_400(client):
    assert_error(upload(client, ("empty.tf", b"")), 400, "invalid_upload")


def test_binary_file_is_400(client):
    assert_error(upload(client, ("bin.tf", b"abc\x00def")), 400, "invalid_upload")


def test_too_many_files_is_400(client):
    files = [(f"f{i}.tf", b"# x\n") for i in range(4)]  # limit in fixture is 3
    assert_error(upload(client, *files), 400, "invalid_upload")


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("broken.tf", b'resource "aws_s3_bucket" "b" {'),
        ("broken.json", b'{"Resources": '),
        ("broken.yaml", b"Resources: [unclosed"),
        ("notcfn.json", b'{"hello": "world"}'),
        ("list.yaml", b"- a\n- b\n"),
    ],
)
def test_malformed_input_is_422_parse_error(client, name, content):
    error = assert_error(upload(client, (name, content)), 422, "parse_error")
    assert name in error["message"]


def test_a_bad_file_fails_the_whole_scan_and_persists_nothing(client, samples):
    good = (samples / "terraform" / "safe.tf").read_bytes()
    r = upload(client, ("good.tf", good), ("bad.tf", b"resource {{{"))
    assert r.status_code == 422
    assert client.get("/api/v1/scans").json()["total"] == 0


@pytest.mark.parametrize("query", ["limit=0", "limit=101", "limit=abc", "offset=-1"])
def test_pagination_validation(client, query):
    assert_error(client.get(f"/api/v1/scans?{query}"), 422, "validation_error")


def test_invalid_severity_filter_is_422(client, samples):
    scan_id = scan_sample(client, samples, "terraform/safe.tf").json()["scan_id"]
    assert_error(
        client.get(f"/api/v1/scans/{scan_id}/findings?severity=bogus"), 422, "validation_error"
    )


def test_openapi_documents_all_v1_endpoints(client):
    paths = client.get("/openapi.json").json()["paths"]
    for path in (
        "/health", "/ready", "/api/v1/scans", "/api/v1/scans/{scan_id}",
        "/api/v1/scans/{scan_id}/findings", "/api/v1/rules", "/api/v1/dashboard/summary",
    ):  # fmt: skip
        assert path in paths, path
    assert "post" in paths["/api/v1/scans"] and "get" in paths["/api/v1/scans"]


def test_unexpected_exception_returns_generic_500(settings, samples):
    class Boom:
        def ping(self):
            raise AssertionError("secret internal detail: /var/db/secret.sqlite")

        def aggregates(self):
            raise RuntimeError("secret internal detail: /var/db/secret.sqlite")

    with TestClient(create_app(settings), raise_server_exceptions=False) as c:
        c.app.state.repository = Boom()
        r = c.get("/api/v1/dashboard/summary")
    assert r.status_code == 500
    assert r.json()["error"]["code"] == "internal_error"
    assert "secret" not in r.text and "/var/db" not in r.text
