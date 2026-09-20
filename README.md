# 🛡️ SentinelGuard AI

**Enterprise Security Guardrail Auditor**

An API-first Infrastructure-as-Code security auditing platform for **Terraform** and **CloudFormation**
with **explainable risk scoring**, automated guardrail detection, and a visual security dashboard.

Upload IaC → get structured findings with severity, evidence and remediation → get a 0–100 Risk Score
that tells you *why* it is what it is. Runs locally, needs **no cloud account, no credentials, no paid
services**, and never executes or applies anything.

| | |
|---|---|
| **Stack** | Python 3.11+ · FastAPI · Pydantic v2 · SQLAlchemy 2 · SQLite · Streamlit · Pytest · Docker · GitHub Actions |
| **Guardrails** | 10 deterministic rules (AWS + Azure) — see [docs/security-baseline.md](docs/security-baseline.md) |
| **Risk score** | Deterministic, 0–100, fully explained — see [docs/risk-scoring.md](docs/risk-scoring.md) |
| **Tests** | 299 automated tests (unit 182 · API 49 · integration 13 · security 43 · dashboard 12) |

---

## Quick start (local, ~2 minutes)

```bash
make install          # creates .venv and installs everything (Python 3.12 recommended)
make api              # API        → http://127.0.0.1:8000   (Swagger UI: /docs)
make dashboard        # Dashboard  → http://localhost:8501   (second terminal)
make seed             # optional: scan all bundled samples so the dashboard has data
```

No `make`? Equivalent commands:

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"
export PYTHONPATH=src            # makes the package importable without relying on the editable install
uvicorn sentinelguard.api.app:create_app --factory --port 8000
SENTINELGUARD_API_BASE_URL=http://127.0.0.1:8000 streamlit run src/sentinelguard/dashboard/app.py
python scripts/seed_demo.py http://127.0.0.1:8000
```

> **Port 8000 already in use?** Pick another: `--port 8010`, and point the dashboard at it with
> `SENTINELGUARD_API_BASE_URL=http://127.0.0.1:8010`. All defaults use `127.0.0.1` (not `localhost`) on purpose: on
> macOS `localhost` can resolve to IPv6 `::1`, where another service may be listening on the same port.

### Docker

```bash
docker compose up --build        # API :8000, dashboard :8501, SQLite persisted in a named volume
# ports busy?  SENTINELGUARD_API_PORT=8020 SENTINELGUARD_DASHBOARD_PORT=8521 docker compose up --build
docker compose down -v           # stop and remove the volume
```

The image runs as a non-root user and needs no secrets.

---

## Try it (API)

```bash
# Scan a deliberately vulnerable Terraform file
curl -s -F "files=@samples/terraform/vulnerable.tf" http://127.0.0.1:8000/api/v1/scans | python3 -m json.tool | head -60

# Scan several files at once (cross-file links such as bucket + public-access-block are resolved)
curl -s -F "files=@main.tf" -F "files=@network.tf" -F "files=@stack.yaml" http://127.0.0.1:8000/api/v1/scans

curl -s http://127.0.0.1:8000/api/v1/scans                              # recent scans
curl -s http://127.0.0.1:8000/api/v1/scans/<scan_id>                    # scan + findings + score breakdown
curl -s "http://127.0.0.1:8000/api/v1/scans/<scan_id>/findings?severity=critical"
curl -s http://127.0.0.1:8000/api/v1/rules                              # the security baseline
curl -s http://127.0.0.1:8000/api/v1/dashboard/summary                  # dashboard aggregates
```

Abbreviated response of `POST /api/v1/scans`:

```jsonc
{
  "scan_id": "9f0c…", "files": ["vulnerable.tf"], "formats": ["terraform"],
  "resources_total": 9, "resources_analyzed": 9, "finding_count": 10,
  "severity_counts": {"critical": 4, "high": 3, "medium": 3, "low": 0},
  "risk_score": 100, "risk_level": "critical",
  "score_breakdown": {
    "method": "Score = sum of the risk weight of every finding … capped at 100 …",
    "raw_total": 210, "score": 100, "cap_applied": true, "escalated": false,
    "by_severity": [{"severity": "critical", "count": 4, "points": 120}, …],
    "contributions": [{"rule_id": "AWS-S3-001", "resource_name": "aws_s3_bucket.public_assets", "severity": "critical", "points": 30}, …]
  },
  "findings": [{
    "finding_id": "…", "scan_id": "9f0c…", "rule_id": "AWS-EC2-001", "provider": "aws",
    "resource_type": "aws_security_group", "resource_name": "aws_security_group.bastion",
    "source_file": "vulnerable.tf", "severity": "critical", "title": "SSH (port 22) is open to the internet",
    "description": "Internet-wide SSH exposes instances to brute force and exploitation.",
    "evidence": ["Ingress tcp/22 (covers SSH port 22) is open to 0.0.0.0/0"],
    "remediation": "Restrict the source to a corporate CIDR/VPN, or remove SSH and use AWS Systems Manager …",
    "risk_weight": 30
  }]
}
```

Errors always use one envelope: `{"error": {"code": "parse_error", "message": "…", "request_id": "…"}}`
(400 invalid upload · 404 not found · 413 too large · 415 unsupported type · 422 parse/validation · 500 generic).

Interactive docs: **Swagger UI `/docs`**, ReDoc `/redoc`, raw schema `/openapi.json`.

---

## What it detects

| Rule | Provider | Severity | Detects |
|---|---|---|---|
| `AWS-S3-001` | AWS | 🔴 Critical | **Public S3 bucket** (public ACL, or policy allowing `Principal "*"`) |
| `AWS-S3-002` | AWS | 🟠 High | S3 Block Public Access missing/disabled |
| `AWS-S3-003` | AWS | 🟡 Medium | No default encryption on bucket |
| `AWS-EC2-001` | AWS | 🔴 Critical | **SSH (22) open to 0.0.0.0/0** or `::/0` |
| `AWS-EC2-002` | AWS | 🔴 Critical | RDP (3389) open to the internet |
| `AWS-EC2-003` | AWS | 🟠 High | All traffic/ports open to the internet |
| `AWS-RDS-001` | AWS | 🟠 High | Publicly accessible database |
| `AWS-ENC-001` | AWS | 🟡 Medium | Unencrypted RDS storage / EBS volume |
| `AZ-STOR-001` | Azure | 🟠 High | Azure storage account/container with anonymous public access |
| `AZ-NSG-001` | Azure | 🔴 Critical | Azure NSG allows SSH/RDP from the internet |

Supported inputs: Terraform `.tf` (AWS + `azurerm`), CloudFormation `.json` / `.yaml` / `.yml` / `.template`
(including short-form intrinsics like `!Ref`, `!Sub`, `!GetAtt`). Terraform `variable` defaults are resolved.

## How the Risk Score works (30-second version)

`score = min(100, Σ weight of every finding)` with weights **Critical 30 · High 20 · Medium 10**.
Levels: **0 secure · 1–19 low · 20–39 medium · 40–69 high · 70–100 critical**; any *critical* finding lifts the
level to at least *high*. The API returns every contribution and the dashboard shows a “Why this score?” panel.
No LLM is involved; the same input always yields the same score. Details: [docs/risk-scoring.md](docs/risk-scoring.md).

## Demo walkthrough (5 minutes)

1. `make api` and `make dashboard`, open <http://localhost:8501> (empty state: score 0, “No scans yet”).
2. `make seed` (or upload files in the sidebar) → refresh. The overview shows the overall score, classification,
   severity counts and charts by severity / provider / rule.
3. In **Scan details**, choose `terraform/vulnerable.tf`: read **Why this score?**, then expand a finding to see
   **evidence** (exact offending value) and **remediation**.
4. Compare with `samples/terraform/safe.tf` (score 0). Try `samples/cloudformation/*.yaml` and `samples/azure/*.tf`.
5. Open <http://127.0.0.1:8000/docs> and call `POST /api/v1/scans` from Swagger.

## Testing

```bash
make test          # 299 tests, ~11 s   (or: PYTHONPATH=src pytest)
make lint          # ruff (includes flake8-bandit security rules)
PYTHONPATH=src pytest tests/security      # adversarial / security-control tests only
PYTHONPATH=src pytest --cov=sentinelguard --cov-report=term-missing
```

| Suite | What it proves |
|---|---|
| `tests/unit` | parsers, value coercion, **every rule with safe + vulnerable IaC (real engine, no mocks)**, scoring boundaries, repository |
| `tests/api` | every endpoint, status codes, validation, error envelope, persistence across restarts, concurrent scans |
| `tests/integration` | parser → rules → scoring → SQLite → retrieval for all 8 sample files; swappable repository |
| `tests/security` | path traversal, oversize/binary/malformed input, YAML python-object tags, Terraform `local-exec`, SQLi, no info leaks, no secrets |
| `tests/dashboard` | the real Streamlit script against a real uvicorn server (Streamlit `AppTest`) |

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs lint, format check and tests on Python 3.11–3.13,
then builds the Docker image and smoke-tests the container.

## Configuration

All via environment variables (see [.env.example](.env.example)); defaults work out of the box.

| Variable | Default | Purpose |
|---|---|---|
| `SENTINELGUARD_DATABASE_URL` | `sqlite:///./data/sentinelguard.db` | Any SQLAlchemy URL |
| `SENTINELGUARD_MAX_UPLOAD_BYTES` | `1048576` | Per-file limit |
| `SENTINELGUARD_MAX_FILES_PER_SCAN` | `10` | Files per request |
| `SENTINELGUARD_LOG_LEVEL` / `_LOG_FORMAT` | `INFO` / `json` | Structured logging |
| `SENTINELGUARD_API_BASE_URL` | `http://127.0.0.1:8000` | Where the dashboard finds the API |

## Repository layout

```
src/sentinelguard/
  api/          FastAPI app, routes, DI, error envelope, request-id middleware
  services/     ScanService, DashboardService (orchestration only)
  parsing/      upload validation · Terraform · CloudFormation · S3 policy analysis · cross-resource linking
  rules/        10 guardrails + registry/engine
  scoring/      deterministic risk scoring
  persistence/  SQLAlchemy ORM, repository interface + implementation
  domain/       shared Pydantic models
  dashboard/    Streamlit UI + HTTP client
samples/        SAFE and VULNERABLE fixtures (Terraform, CloudFormation JSON/YAML, Azure)
tests/          unit · api · integration · security · dashboard
docs/           PLAN · architecture · security-baseline · risk-scoring · security-review · presentation
```

Architecture and design decisions: [docs/architecture.md](docs/architecture.md) · the original plan:
[docs/PLAN.md](docs/PLAN.md) · AI-development audit log: [prompts.md](prompts.md).

## Safety guarantees

* IaC is parsed as **data** (`python-hcl2`, `json`, `yaml` SafeLoader subclass). Terraform is never invoked;
  no `eval`, `exec`, `subprocess`, or shell — enforced by a static test.
* Uploads are held in memory only, size- and type-limited, and **never written to disk or stored** in the DB
  (only findings are persisted).
* No AWS/Azure SDKs, no credentials. Remediation is **advice text only**; nothing is ever applied to real infrastructure.
* Errors never leak stack traces, file paths or internals.

## Known limitations

* **Static analysis only.** Values that cannot be resolved statically (module outputs, `locals`, `for_each`,
  data sources, CloudFormation `Fn::If`/parameters) are treated as *unknown* and **not flagged** — the tool prefers
  false negatives over guessing. Only `variable` defaults and literal values are resolved.
* Terraform `module` blocks, `dynamic` blocks and `count`/`for_each` expansion are not evaluated; `.tf.json`,
  Bicep and ARM templates are not supported (rejected with a clear 415/422).
* Azure NSG rule **priority is not evaluated** (a higher-priority Deny for the same port is not considered).
* Account-level controls (S3 account Block Public Access, default EBS encryption) are invisible to a file scan, so
  `AWS-S3-002`/`AWS-ENC-001` can be noisy where those are enforced elsewhere.
* No authentication/authorisation, rate limiting or multi-tenancy: intended for local/CI use. Put it behind an
  authenticated reverse proxy (which should also cap request size and time) before exposing it.
* Line numbers are not reported (the HCL parser does not expose them). SQLite is the default;
  schema is created with `create_all` (no migrations yet).
* One large adversarial file can still consume CPU while parsing (bounded by the 1 MB default limit).

## Future improvements

Terraform module/`locals`/`for_each` resolution and plan-JSON (`terraform show -json`) input · ARM/Bicep ·
more rules (IAM wildcards, CloudTrail, KMS rotation, Azure Key Vault/SQL) with CIS/NIST mapping · SARIF export and a
CI/PR-comment mode · authentication + per-team projects · Alembic migrations and PostgreSQL · suppressions/exceptions
with expiry · trend charts across scans · optional (clearly separated) LLM-written remediation *explanations*
that never influence the score.
