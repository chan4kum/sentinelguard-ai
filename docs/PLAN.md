# SentinelGuard AI — Part 1: Architecture & Multi-Agent Implementation Plan

*Enterprise Security Guardrail Auditor.* Owner: **Lead Architect Agent**. Static analysis only — uploaded IaC is
untrusted **data** and is never executed.

> **Status note (honest record).** This plan is the reconciled Part 1 deliverable. Under the first prompt's
> "proceed automatically" instruction, Parts 2–3 were already executed in this repository before the
> "Part 1 only" prompt arrived; all code work stopped when that prompt was received. File/fixture names below refer
> to what exists in the repo so every rule can be traced to a real fixture.

## 1. Final MVP scope

**In scope**
1. Python + FastAPI, API-first (versioned `/api/v1`, OpenAPI/Swagger).
2. SQLite + SQLAlchemy (repository interface so the store is swappable).
3. Streamlit dashboard that **only calls the API**.
4. Static analysis of **Terraform (`.tf`)** and **CloudFormation (JSON/YAML)**; Azure via Terraform `azurerm_*` only.
5. **10** deterministic guardrails (8 AWS, 2 Azure) each with evidence + remediation.
6. Explainable 0–100 Risk Score (no LLM).
7. pytest suite, Docker (+Compose), GitHub Actions CI, structured JSON logging, env-based config.
8. No cloud credentials, no cloud resources, no destructive or automatic remediation.

**Out of scope** (documented as limitations): Terraform module/`locals`/`for_each`/`dynamic` evaluation, `.tf.json`,
ARM/Bicep, plan-file input, authentication, migrations, multi-tenancy, LLM features.

## 2. Architecture

`API → Scan Service → (IaC Parser + Normalizer → Rules Engine → Risk Scoring) → Repository → SQLite`;
`Streamlit → API`. The parser, rules and scoring layers are **pure functions** (no I/O), so each is testable alone.
The dashboard contains **zero** security logic: it renders API responses (including the score explanation).

## 3. Architecture diagram

```
 Streamlit dashboard ──HTTP──► FastAPI  (routes · validation · error envelope · request-id logging)
                                  │
                              ScanService / DashboardService      (orchestration only)
                 ┌────────────────┼──────────────────┬──────────────────┐
         Ingest + Parse       Rules Engine       Risk Scoring        Repository (ABC)
        (TF, CFN → normalized) (10 rules)       (Σ weights, cap)     └─ SQLAlchemy ─► SQLite
```

## 4. Repository structure

```
src/sentinelguard/  config · logging_config · errors
  domain/models.py            api/{app,deps,schemas,routes/*}
  parsing/{ingest,values,policy,terraform,cloudformation,linking}
  rules/{base,aws,azure,registry}   scoring/engine   services/{scan,dashboard}_service
  persistence/{database,orm,repository}   dashboard/{client,app}
samples/{terraform,cloudformation,azure}/{safe,vulnerable}.*      tests/{unit,api,integration,security,dashboard}
docs/  scripts/seed_demo.py  Dockerfile  docker-compose.yml  .github/workflows/ci.yml  pyproject.toml  Makefile
README.md  prompts.md
```

## 5. Agent responsibility matrix (10 agents, one owner per module)

| Agent | Owns (writes) | Does **not** touch |
|---|---|---|
| Lead Architect | plan, `domain/`, `services/`, wiring/integration decisions | rule logic, UI |
| IaC Parser | `parsing/` | rules, DB |
| Security Guardrail | `rules/`, `scoring/`, `samples/` | parsing, API |
| API/Platform | `api/`, `errors.py` | rule logic |
| Persistence | `persistence/` | API, rules |
| Dashboard | `dashboard/` | scoring/rules (must not duplicate) |
| Testing | `tests/` (all suites incl. E2E smoke) | production code |
| Security Review | read-only review + adversarial cases handed to Testing; findings go back to the owner | writes no production code |
| DevOps | `config.py`, `logging_config.py`, Docker, CI, `.env.example`, Makefile | business logic |
| Documentation | README, `docs/`, `prompts.md`, presentation | code |

## 6. Security-rule matrix (10 rules; every rule has a vulnerable **and** a safe fixture)

**A — definition**

| ID | Provider · IaC · resource type | Misconfiguration | Detection condition | Sev · weight |
|---|---|---|---|---|
| AWS-S3-001 | AWS · TF+CFN · `aws_s3_bucket(_acl/_policy)` / `AWS::S3::Bucket(Policy)` | Public bucket | ACL ∈ {public-read, public-read-write, authenticated-read} **or** unconditional policy Allow with `Principal "*"` | CRITICAL · 30 |
| AWS-S3-002 | AWS · TF+CFN · S3 bucket (+`public_access_block`) | Block Public Access missing/off | no PAB linked, or any of the 4 flags false (TF omitted flag = false) | HIGH · 20 |
| AWS-S3-003 | AWS · TF+CFN · S3 bucket | No default encryption | no SSE config resource/block (TF) / no `BucketEncryption` (CFN) | MEDIUM · 10 |
| AWS-EC2-001 | AWS · TF+CFN · security group / ingress rule | SSH open to world | tcp ingress range covers 22 with source `0.0.0.0/0` or `::/0` (not an all-ports rule) | CRITICAL · 30 |
| AWS-EC2-002 | AWS · TF+CFN · security group / ingress rule | RDP open to world | same, port 3389 | CRITICAL · 30 |
| AWS-EC2-003 | AWS · TF+CFN · security group / ingress rule | Over-permissive ingress | protocol `-1` or ports 0–65535 from the world | HIGH · 20 |
| AWS-RDS-001 | AWS · TF+CFN · `aws_db_instance` / `AWS::RDS::DBInstance` | Public database | `publicly_accessible` / `PubliclyAccessible` = true | HIGH · 20 |
| AWS-ENC-001 | AWS · TF+CFN · RDS instance/cluster, EBS volume | Unencrypted storage | encryption flag false **or omitted** (unknown/inherited ⇒ not flagged) | MEDIUM · 10 |
| AZ-STOR-001 | Azure · TF · `azurerm_storage_account`, `azurerm_storage_container` | Anonymous public access | `allow_nested_items_to_be_public`/`allow_blob_public_access` = true, or container access `blob`/`container` | HIGH · 20 |
| AZ-NSG-001 | Azure · TF · `azurerm_network_security_group/_rule` | SSH/RDP from Internet | Inbound + Allow + tcp/`*` + source `*`/`Internet`/`0.0.0.0/0` covering 22 or 3389 | CRITICAL · 30 |

**B — evidence, remediation, fixtures** (all fixtures exist in the repo)

| ID | Evidence returned | Remediation (summary) | Vulnerable fixture (MUST fire) | Safe fixture (MUST NOT fire) |
|---|---|---|---|---|
| AWS-S3-001 | `ACL is "public-read" (set by aws_s3_bucket_acl.x)` / `Bucket policy statement "Sid" allows Principal "*"` | private ACL, drop `*` principals, enable PAB | `terraform/vulnerable.tf` (`public_assets`, `policy_open`); `cloudformation/vulnerable.json` `PublicBucket`; `.yaml` `LogsBucket` | `terraform/safe.tf` `data`; `cloudformation/safe.json` `PrivateBucket` |
| AWS-S3-002 | `Public access block setting(s) disabled: …` / `No public access block is configured` | add PAB, all four true | `vulnerable.tf` `public_assets`; `vulnerable.json` `PublicBucket` | `safe.tf` PAB all true; `safe.yaml` `DataBucket` |
| AWS-S3-003 | `No server-side encryption configuration found` | add SSE (kms/AES256) | `vulnerable.tf` `public_assets`; `vulnerable.json` | `safe.tf` (SSE resource); `safe.yaml` |
| AWS-EC2-001 | `Ingress tcp/22 (covers SSH port 22) is open to 0.0.0.0/0` | restrict CIDR / use SSM | `vulnerable.tf` `bastion` (via `var` default); `vulnerable.json` `OpenSecurityGroup`; `vulnerable.yaml` `SshFromAnywhere` | `safe.tf` `web` (22 from `10.0.0.0/16`); `safe.json` `WebSecurityGroup` |
| AWS-EC2-002 | `Ingress tcp/3389 … open to ::/0` | restrict / bastion | `vulnerable.tf` `bastion` (IPv6); `vulnerable.json` | unit fixture: 3389 from `192.168.0.0/16` |
| AWS-EC2-003 | `Ingress allowing all protocols/ports is open to 0.0.0.0/0` | specific ports + sources | `vulnerable.tf` `wide_open` | unit fixture: `-1` from `10.0.0.0/8`; 443-only (`safe.tf`) |
| AWS-RDS-001 | `publicly_accessible = true` | private subnets, false | `vulnerable.tf` `orders`; `vulnerable.json` `Database` | `safe.tf` `orders` (false); `safe.json` |
| AWS-ENC-001 | `storage_encrypted is false or not set …` | enable (KMS) | `vulnerable.tf` `orders`,`scratch`; `vulnerable.json` `Database`,`DataVolume`; `.yaml` `ScratchVolume` | `safe.tf`/`safe.json` encrypted; snapshot-derived ⇒ unknown |
| AZ-STOR-001 | `allow_nested_items_to_be_public = true: anonymous public access is enabled` | disable, private containers | `azure/vulnerable.tf` `public`, `open` | `azure/safe.tf` |
| AZ-NSG-001 | `Rule "allow-ssh-any" allows Inbound from * to SSH (22)` | scope source / Bastion / JIT | `azure/vulnerable.tf` `web` (SSH `*`), `rdp` (Internet) | `azure/safe.tf` (10/8 allow, Deny rule, 443) |

Not included because they cannot be tested reliably in the MVP: IAM wildcard analysis, KMS rotation, CloudTrail,
Azure Key Vault/SQL, anything needing module/`locals` resolution.

## 7. Risk-scoring design

`score = min(100, Σ risk_weight)`; weights per rule: **Critical 30 · High 20 · Medium 10** (Low 4 reserved).
Bands: **0 secure · 1–19 low · 20–39 medium · 40–69 high · 70–100 critical**; a CRITICAL finding lifts the *level*
to at least *high* (flagged `escalated`). **Multiple findings** add up, counted once per (rule, resource);
**bounded** by the cap (`cap_applied`, `raw_total` reported). **Explanation** — every scan response carries
`score_breakdown`: method text, raw total, cap/escalation flags, per-severity subtotals and one contribution line per
finding; `Σ contributions == raw_total` (tested). Integers only, deterministic, no LLM. Dashboard "overall" = rounded
mean of scan scores (with latest/highest shown).

## 8. API contracts (`/api/v1`; errors use `{"error":{"code","message","details?","request_id"}}`)

| Endpoint | Purpose | Request | Success | Errors / validation |
|---|---|---|---|---|
| `GET /health` | liveness | – | 200 `{status,service,version}` | – |
| `GET /ready` | DB reachable | – | 200 `{status:"ready",database:"ok"}` | 503 when DB down |
| `POST /api/v1/scans` | scan files | multipart `files` (1..10 × `.tf/.json/.yaml/.yml/.template`, ≤1 MiB) | **201** `ScanDetail` (scan + findings + `score_breakdown`) | 400 empty/binary/too many · 413 too large · 415 bad type · 422 malformed/non-CFN/missing field |
| `GET /api/v1/scans` | list newest-first | `limit` 1–100 (20), `offset`≥0 | 200 `{items,total,limit,offset}` | 422 bad paging |
| `GET /api/v1/scans/{id}` | scan detail | – | 200 `ScanDetail` | 404 unknown id |
| `GET /api/v1/scans/{id}/findings` | findings, most severe first | `severity?` enum | 200 `[Finding]` | 404 · 422 bad severity |
| `GET /api/v1/rules` | baseline catalogue | – | 200 `[Rule]` (id, provider, kinds, description, detection, severity, weight, remediation) | – |
| `GET /api/v1/dashboard/summary` | aggregates | – | 200 totals, overall score/level, by severity/provider/rule, 5 recent scans, explanation | – |

`Finding`: `finding_id, scan_id, rule_id, provider, resource_type, resource_name, source_file, severity, title,
description, evidence[], remediation, risk_weight`.

## 9. Database schema (2 tables; rules live in code, so no `rules` table)

`scans(scan_id PK, created_at, files JSON, formats JSON, resources_total, resources_analyzed, finding_count,
critical/high/medium/low_count, risk_score, risk_level, score_breakdown JSON)` —
`findings(finding_id PK, scan_id FK→scans ON DELETE CASCADE, rule_id, provider, resource_type, resource_name,
source_file, severity, title, description, evidence JSON, remediation, risk_weight)`; indexes on
`findings.scan_id`, `findings.rule_id`, `scans.created_at`. **Uploaded content is never stored.**

## 10. Normalized IaC model

`NormalizedResource{provider, kind, source_type, name, source_format, source_file, properties}` with canonical kinds
`s3_bucket, security_group, rds_instance, ebs_volume, azure_storage, azure_nsg` (+ auxiliary S3 kinds merged into
the bucket by a linker, including across files). Terraform `type.name` / CloudFormation logical ID is the reference key.
`security_group.ingress = [{from_port,to_port,protocol,cidrs}]`. Values not statically known → `None` → **never flagged**.
Terraform `variable` defaults are the only resolved references.

## 11. Security / threat controls

| Threat | Control | Verified by |
|---|---|---|
| Unsafe YAML | `SafeLoader` subclass + CFN short-form tags only; python/object tags rejected → 422 | adversarial tests, static "SafeLoader subclass" test |
| Arbitrary code execution | parse-as-data only; no `eval/exec/pickle`; Terraform `local-exec`/`external` treated as text | static source guard + marker-file tests |
| Terraform execution | `python-hcl2` parser only; no `terraform` binary, no providers/modules fetched | test with `local-exec` + monkeypatched `subprocess` |
| Shell/command execution | none in code base (banned-token static test, ruff-S/bandit) | static test |
| Path traversal | filename reduced to a basename *label*, extension kept on truncation; never used as a path; uploads never written to disk | traversal tests assert no files created |
| Unsupported files | extension allow-list (415), NUL/UTF-8 checks (400) | tests |
| File-size limits | per-file cap (default 1 MiB, read capped at limit+1), `Content-Length` pre-check, max 10 files | tests |
| Malformed input | typed `IaCParseError` (422) naming file + line/column only; recursion guarded | malformed-input matrix |
| Secrets | none in code/repo; `.env` ignored; DB stores findings, not content; no cloud SDKs | secret-scan + DB-bytes test |
| Sensitive errors | one envelope; generic 500 with `request_id`; no traces/paths/library names | leak tests |
| Injection / XSS | SQLAlchemy parameters only; dashboard renders user text as text, never HTML | SQLi + hostile-name tests |

## 12. Task breakdown (26 tasks · one agent · one task · implement → test → verify → next)

| ID | Task | Agent | Inputs → Output | Depends on | Acceptance criteria | Required tests |
|---|---|---|---|---|---|---|
| T01 | Domain models & enums | Architect | brief → `domain/models.py` | – | all models validate; enums cover severities/providers/levels | model validation |
| T02 | Config + structured logging | DevOps | env → `config.py`, `logging_config.py` | – | env overrides work; absurd limits rejected; JSON logs carry request id | config, log-format tests |
| T03 | Error types | API | – → `errors.py` | – | each error has code + HTTP status | mapping test |
| T04 | SQLite engine + ORM tables | Persistence | T01,T02 → `database.py`,`orm.py` | T01,T02 | empty DB gets both tables; idempotent init | init tests |
| T05 | Repository interface + SQLAlchemy impl | Persistence | T04 → `repository.py` | T04 | save/get/list/filter/aggregate round-trip, ping | repository tests |
| T06 | FastAPI factory, middleware, `/health`, `/ready` | API | T02,T03,T05 → `api/app.py` | T02,T03,T05 | 200/503 behave; error envelope; request-id | health/ready/404/405 tests |
| T07 | Upload validation | IaC Parser | bytes → validated `IacFile` | T03 | traversal/ext/size/NUL/UTF-8 handled | ingest tests |
| T08 | Value coercion helpers | IaC Parser | – → `values.py` | – | unknown ⇒ `None`; ports/CIDR/protocol normalised | table tests |
| T09 | Terraform normalizer (+variable defaults) | IaC Parser | T07,T08 → resources | T07,T08 | sample TF → expected resources; malformed → safe 422 | parser + malformed tests |
| T10 | CloudFormation normalizer (JSON/YAML/tags) | IaC Parser | T07,T08 → resources | T07,T08 | JSON+YAML+`!Ref/!Sub/!GetAtt`; python tags rejected | parser + unsafe-YAML tests |
| T11 | S3 policy analysis + cross-resource linker | IaC Parser | T09,T10 → linked buckets | T09,T10 | ACL/PAB/policy/SSE merged, also across files | linking tests |
| T12 | Safe + vulnerable fixtures | Guardrail | rule matrix → `samples/` | T01 | each rule has both fixture kinds; expected counts documented | fixture contract tests |
| T13 | Rule interface, registry, engine | Guardrail | T01 → `rules/base,registry` | T01 | 10 unique complete rules; deterministic order | catalogue tests |
| T14 | S3 rules (001/002/003) | Guardrail | T11,T12,T13 | T11–T13 | fires on vulnerable, silent on safe (TF+CFN) | per-rule safe/vuln, **no mocks** |
| T15 | Network rules (EC2-001/002/003) | Guardrail | T09,T10,T12,T13 | T09,T10,T12,T13 | ranges, IPv6, all-ports without double count | per-rule matrix |
| T16 | Database/storage rules (RDS-001, ENC-001) | Guardrail | same | same | omitted ⇒ unencrypted; inherited/unknown ⇒ silent | per-rule matrix |
| T17 | Azure rules (STOR-001, NSG-001) | Guardrail | T09,T12,T13 | T09,T12,T13 | direction/access/protocol/ports/sources honoured | per-rule matrix |
| T18 | Scoring engine | Guardrail | T01 → `scoring/engine.py` | T01 | bands, cap, escalation, explanation sums | boundary/determinism tests |
| T19 | Scan + dashboard services | Architect | T05,T07–T18 → `services/` | T05,T11,T14–T18 | parse→rules→score→persist atomically; nothing saved on failure | integration tests over all fixtures |
| T20 | Scan/rules/dashboard routes | API | T06,T19 → `routes/` | T06,T19 | contracts in §8 incl. status codes | API contract + error tests |
| T21 | API client + Streamlit dashboard | Dashboard | T20 → `dashboard/` | T20 | shows score, level, counts, charts, recent scans, evidence, remediation, "why this score"; no business logic | Streamlit `AppTest` vs live API |
| T22 | Docker, Compose, `.env.example`, `.gitignore` | DevOps | T20,T21 | T20,T21 | image builds, non-root, container smoke passes | container smoke |
| T23 | GitHub Actions CI + lint | DevOps | T20 | T20 | lint + tests on 3.11–3.13, docker job | CI config review, local ruff |
| T24 | Security review + adversarial suite | Security Review + Testing | all code | T20 | every §11 control evidenced; findings fixed by owners | security suite, bandit, pip-audit |
| T25 | End-to-end smoke + regression | Testing | T21,T22 | T21,T22 | live API + dashboard + container scans of all 8 fixtures | smoke scripts, full suite |
| T26 | Documentation + presentation + audit log | Documentation | all | T21 | README/architecture/baseline/scoring/limitations/presentation, `prompts.md` complete | doc run-through |

## 13. Task dependency graph

```
T01 ─┬─► T04 ─► T05 ─────────────────────────────┐
T02 ─┤                                            ├─► T06 ─┐
T03 ─┘─► T07 ─┬─► T09 ─┐                          │        │
        T08 ─┴─► T10 ─┴─► T11 ─┐                  │        │
T01 ─► T12 ────────────────────┤                  │        ├─► T20 ─► T21 ─► T22/T23 ─► T25 ─► T26
T01 ─► T13 ─► T14,T15,T16,T17 ─┼─► T19 ────────────┴────────┘          └────────────► T24 ─┘
T01 ─► T18 ────────────────────┘
```

## 14. Testing strategy

Unit (helpers, config, errors) · Parser (TF/CFN/YAML/JSON, malformed, unknown⇒`None`) · **Rule** (each rule:
vulnerable fires, safe silent, edge cases; real engine, no mocks) · Risk-score (every band boundary, cap, escalation,
sum of contributions) · API (every endpoint, statuses, validation, envelope, concurrency) · Persistence (round-trip,
paging, aggregates, survives restart, swappable repository) · Integration (parser→rules→score→SQLite→API for all
fixtures) · Security/adversarial (traversal, oversize, binary, YAML tags, `local-exec`, SQLi, XSS, leaks, secrets,
static no-exec guard) · Dashboard (AppTest against a live server) · E2E smoke (live uvicorn + Streamlit + container).

## 15. Definition of Done

Working API (all §8 endpoints) · Terraform **and** CloudFormation scanning · every rule fires on its vulnerable and stays
silent on its safe fixture · Risk Score visible and explained in API and UI · SQLite persistence (survives restart) ·
Streamlit dashboard verified against a live API · automated tests green, zero skipped/failing · adversarial suite green ·
`docker build` + container smoke pass · CI workflow present and lint-clean · README, architecture, security baseline,
risk-scoring doc, `prompts.md`, `presentation.md` present · no cloud resources or credentials · limitations documented.

## 16. Estimated implementation sequence (≈ 4.5–5 h, inside the 4–6 h goal)

| Phase | Tasks | Est. |
|---|---|---|
| A Foundation | T01–T06 | 40 min |
| B Parsing | T07–T11 | 60 min |
| C Guardrails + fixtures | T12–T17 | 55 min |
| D Scoring | T18 | 15 min |
| E Services + API | T19–T20 | 40 min |
| F Dashboard | T21 | 30 min |
| G Platform | T22–T23 | 25 min |
| H Verification | T24–T25 | 40 min |
| I Documentation | T26 | 25 min |

## 17. Architecture critique (and resulting simplifications)

| Question | Finding → decision |
|---|---|
| Anything unnecessarily complicated? | Yes: a plugin loader for rules, Alembic, an Integration Agent, a `rules` table, a DTO layer. **Removed** — plain registry list, `create_all`, integration folded into Architect/Testing, rules in code, domain models reused as API schemas. |
| Anything removable and still satisfy the brief? | Multi-file scans and cross-file linking are optional but cheap and needed for real Terraform (bucket and its PAB live in different files) → **kept**. ARM/Bicep/`.tf.json` → **cut**. |
| Overlapping agent responsibilities? | Testing vs Security Review and Architect vs Integration overlapped. **Resolved:** Testing writes all tests; Security Review is read-only and hands cases to Testing; integration wiring belongs to the Architect (services). |
| Are all rules testable? | All 10 have concrete safe+vulnerable fixtures. **Weakest points:** S3 policy detection when `jsonencode` contains unresolved references falls back to a text heuristic (evidence is labelled `[text heuristic]`); Azure NSG **priority is not evaluated** (a higher-priority Deny is ignored). Both are documented limitations, not silent claims. |
| Terraform and CloudFormation consistent? | Yes for AWS rules via the normalized model. Azure rules are **Terraform-only** (ARM out of scope); CloudFormation is AWS-only by definition. |
| AWS/Azure claims limited to what is supported? | Yes: README says "AWS (TF+CFN)" and "Azure (Terraform `azurerm_*`)" only; unknown values are not flagged. Account-level controls (S3 account PAB, default EBS encryption) are invisible to file scans — noted. |
| Achievable in the time window? | Yes: ≈ 4.5–5 h estimate; scope kept to 10 rules and 26 small tasks. |

**Result:** plan is internally consistent; no further changes required before Part 2 (already executed — see status note).
