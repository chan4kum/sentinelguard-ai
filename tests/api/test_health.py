from __future__ import annotations


def test_health_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "SentinelGuard AI"
    assert "X-Request-ID" in r.headers


def test_ready_ok(client):
    r = client.get("/ready")
    assert r.status_code == 200
    assert r.json() == {"status": "ready", "database": "ok"}


def test_ready_503_when_database_down(client):
    class DownRepo:
        def ping(self):
            return False

    client.app.state.repository = DownRepo()
    r = client.get("/ready")
    assert r.status_code == 503
    assert r.json() == {"status": "unavailable", "database": "error"}


def test_unknown_route_uses_error_envelope(client):
    r = client.get("/nope")
    assert r.status_code == 404
    err = r.json()["error"]
    assert err["code"] == "not_found"
    assert err["request_id"]


def test_wrong_method_uses_error_envelope(client):
    r = client.post("/health")
    assert r.status_code == 405
    assert r.json()["error"]["code"] == "method_not_allowed"


def test_request_id_is_echoed_when_safe_and_replaced_when_not(client):
    assert (
        client.get("/health", headers={"X-Request-ID": "abc-123"}).headers["X-Request-ID"]
        == "abc-123"
    )
    replaced = client.get("/health", headers={"X-Request-ID": "bad id\twith spaces"})
    assert replaced.headers["X-Request-ID"] != "bad id\twith spaces"


def test_openapi_and_docs_available(client):
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200
