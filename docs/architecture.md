# Architecture

SentinelGuard AI is a layered, API-first application. Each layer has one job and depends only on the layer
below it, so the database, the parsers, or the UI can be replaced without touching business logic.

```
                      ┌──────────────────────────┐
                      │  Streamlit dashboard     │  HTTP only — no DB access, no shared code paths
                      └────────────┬─────────────┘
                                   │  REST /api/v1  (JSON)
┌──────────────────────────────────▼──────────────────────────────────┐
│ API layer            FastAPI · routes · DI · error envelope · logging│
├─────────────────────────────────────────────────────────────────────┤
│ Service layer        ScanService · DashboardService  (orchestration) │
├─────────────┬──────────────────┬───────────────────┬────────────────┤
│ Ingestion & │  Rules engine    │  Risk scoring     │ Repository     │
│ parsing     │  10 guardrails   │  deterministic    │ interface (ABC)│
│ (pure)      │  (pure)          │  (pure)           │                │
├─────────────┴──────────────────┴───────────────────┼────────────────┤
│ Domain models (Pydantic) — shared vocabulary       │ SQLAlchemy impl│
└────────────────────────────────────────────────────┴───────┬────────┘
                                                              │
                                                       SQLite (default)
```

## Request flow: `POST /api/v1/scans`

1. **API** reads the multipart `files` (each capped at `max_upload_bytes + 1`), after a `Content-Length` pre-check.
2. **ScanService** →
   1. `parsing.ingest.validate_upload` — sanitise the filename to a label, allow-list the extension, check size,
      emptiness, NUL bytes and UTF-8.
   2. `parsing.parse_files` — Terraform (`python-hcl2`) or CloudFormation (`json` / `yaml` SafeLoader) →
      **normalized resources**; then the *linker* folds ACL / policy / public-access-block / encryption resources
      into their bucket (also across files).
   3. `rules.registry.evaluate_resources` — every rule × every applicable resource → `Finding`s.
   4. `scoring.engine.calculate_risk` — findings → score, level and the full explanation.
   5. `repository.save_scan` — one transaction for the scan and all its findings.
3. The `ScanDetail` (scan + findings + score breakdown) is returned with `201`.

Failure at any step raises a typed `SentinelError` → the API returns the standard error envelope and **nothing is
persisted**.

## Layers and responsibilities

| Layer | Package | Rule of thumb |
|---|---|---|
| Domain | `domain/` | Pure Pydantic data. Imported by everyone, imports nothing from the app. |
| Parsing | `parsing/` | Bytes/text in, `NormalizedResource` out. No rules, no DB, no HTTP. |
| Rules | `rules/` | `GuardrailRule.evaluate(resource) -> list[str]` evidence. Pure and independently testable. |
| Scoring | `scoring/` | `list[Finding] -> ScoreBreakdown`. Pure arithmetic. |
| Persistence | `persistence/` | `ScanRepository` ABC + SQLAlchemy implementation. Only this layer knows SQL. |
| Services | `services/` | Wires the pure layers to the repository. No HTTP, no SQL. |
| API | `api/` | Translates HTTP ⇄ services; owns the error envelope. |
| Dashboard | `dashboard/` | Calls the API through `ApiClient`. |

## The normalized resource model

Both Terraform and CloudFormation are mapped to the same canonical kinds so each rule is written **once**:

```
NormalizedResource { provider, kind, source_type, name, source_format, source_file, properties }

kinds: s3_bucket · security_group · rds_instance · ebs_volume · azure_storage · azure_nsg
aux  : s3_acl · s3_public_access_block · s3_bucket_policy · s3_encryption   (merged into s3_bucket by the linker)
```

`aws_security_group.ingress`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`,
`AWS::EC2::SecurityGroup` and `AWS::EC2::SecurityGroupIngress` all become `security_group` with a list of
`{from_port, to_port, protocol, cidrs}`. Anything that cannot be determined statically is `None` and is never flagged.

## Database schema

```
scans(scan_id PK, created_at, files JSON, formats JSON, resources_total, resources_analyzed, finding_count,
      critical_count, high_count, medium_count, low_count, risk_score, risk_level, score_breakdown JSON)
findings(finding_id PK, scan_id FK → scans ON DELETE CASCADE, rule_id, provider, resource_type, resource_name,
         source_file, severity, title, description, evidence JSON, remediation, risk_weight)
indexes: findings(scan_id), findings(rule_id), scans(created_at)
```

Raw uploaded content is deliberately **not** stored (it may contain secrets). SQLite runs in WAL mode with foreign
keys on. Tables are created at startup (`create_all`), which is idempotent.

## Design decisions

| Decision | Why |
|---|---|
| Parse as data, never execute | The tool ingests untrusted files; `terraform`/shell are never involved. |
| Canonical model + per-rule evidence | One rule works for Terraform *and* CloudFormation; findings always carry proof. |
| Unknown ⇒ not flagged | A security tool that guesses erodes trust; false negatives are documented, false positives avoided. |
| One finding per (rule, resource) | Score stays fair and explainable; evidence lists every offending item. |
| No LLM in scoring | Determinism and auditability are the product. |
| Repository ABC | The brief requires swappable persistence; verified by an in-memory fake in tests. |
| Domain models reused as API schemas | Avoids a parallel DTO layer for a small API. |
| Dashboard over HTTP | Proves the API is complete and keeps the UI replaceable. |
| `create_all` instead of Alembic | Single-version MVP; migration path documented. |
| Streamlit + Altair (no plotly) | Fewer dependencies; Altair ships with Streamlit. |

## Replacing components

* **Database** — set `SENTINELGUARD_DATABASE_URL` to any SQLAlchemy URL (e.g. PostgreSQL), or implement
  `ScanRepository` for a non-SQL store and construct it in `api/app.py`.
* **New IaC format** — add a parser that emits `NormalizedResource`s; existing rules apply unchanged.
* **New rule** — subclass `GuardrailRule`, add it to `BASELINE`, add safe/vulnerable tests.
* **New UI/CLI** — talk to `/api/v1`.

## Observability & operations

Structured JSON logs (stdout) with a per-request `request_id` (also returned as `X-Request-ID`); `/health`
(liveness) and `/ready` (DB check); Docker `HEALTHCHECK`; the container runs as a non-root user.
