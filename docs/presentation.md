---
marp: true
theme: default
paginate: true
title: SentinelGuard AI — Enterprise Security Guardrail Auditor
---
<!-- Convert: `npx @marp-team/marp-cli docs/presentation.md --pptx`  (or paste each "---" section into a slide) -->

# 🛡️ SentinelGuard AI
### Enterprise Security Guardrail Auditor

An API-first Infrastructure-as-Code security auditing platform for **Terraform** and **CloudFormation**
with **explainable risk scoring**, automated guardrail detection and a visual dashboard.

*Graduate Vibe Coding Challenge — Project 2 · built end-to-end with one AI tool (Claude Code)*

---

## 1. Problem & objective

* Misconfigured cloud infrastructure (public buckets, open SSH) is a leading cause of breaches — and it is visible **in the code, before deployment**.
* Objective: audit Terraform / CloudFormation against a security baseline, flag high-risk patterns, and present a **Risk Score** anyone can understand.
* Constraints: Python · API-first · free database · runs locally · **no cloud account, no credentials, no execution of uploaded code**.

---

## 2. Architecture

```
Streamlit ──HTTP──► FastAPI ─► Scan Service ─┬─► Parse + Normalize
                                             ├─► Rules Engine (10 rules)
                                             ├─► Risk Scoring
                                             └─► Repository ─► SQLite
```

* Parser, rules and scoring are **pure functions** — independently testable.
* Repository interface → swap SQLite for PostgreSQL without touching business logic.
* Dashboard has **zero** security logic: it renders what the API explains.

---

## 3. Multi-agent AI development workflow

* Lead Architect plans → 10 logical agents, **one owner per module, one small task at a time**.
* 26 tasks: *implement → unit-verify → integrate → end-to-end verify*, in dependency order.
* Parser · Guardrail · API · Persistence · Dashboard · DevOps · Testing · Security Review · Documentation.
* **No manual code edits**; every fix (e.g. filename truncation bug, a Bandit finding) went back through the owning agent.
* Every prompt is recorded in `prompts.md`; the timer and elapsed time were reported each turn.

---

## 4. IaC parsing & normalization

* Terraform via `python-hcl2`; CloudFormation JSON/YAML via a **SafeLoader** subclass (`!Ref`, `!Sub`, `!GetAtt`…).
* Both map to one **normalized model** (`s3_bucket`, `security_group`, `rds_instance`, `ebs_volume`, `azure_storage`, `azure_nsg`) → each rule written **once**.
* Linker merges an S3 bucket with its ACL / policy / public-access-block / encryption — even across files.
* Terraform `variable` defaults are resolved. **Unknown ⇒ never flagged** (no guessing).

---

## 5. Security guardrails (10 rules)

| | | |
|---|---|---|
| 🔴 **S3 public** | 🔴 **SSH 22 open** | 🔴 **RDP 3389 open** |
| 🟠 S3 Block Public Access off | 🟠 All-traffic ingress | 🟠 Public database |
| 🟡 S3 no encryption | 🟡 Unencrypted RDS/EBS | 🟠 Azure public storage |
| 🔴 Azure NSG SSH/RDP from Internet | | |

Each rule ships with ID, provider, detection condition, severity, weight, **evidence** and **remediation**.

---

## 6. Explainable Risk Score

`score = min(100, Σ finding weights)` · Critical **30** · High **20** · Medium **10**

* Bands: 0 secure · 1–19 low · 20–39 medium · 40–69 high · 70–100 critical
* Any **critical** finding lifts the level to at least *high*
* API returns method, raw total, cap/escalation flags, per-severity subtotals and **one line per finding**
* Deterministic, integer-only, **no LLM** in the score

---

## 7. API-first design

`POST /api/v1/scans` · `GET /api/v1/scans[/{id}[/findings]]` · `GET /api/v1/rules` · `GET /api/v1/dashboard/summary` · `GET /health` · `GET /ready`

* Multipart upload of 1–10 files · OpenAPI/Swagger at `/docs`
* One error envelope: `{"error": {"code", "message", "request_id"}}` — 400/404/413/415/422, generic 500
* Structured JSON logs with request IDs · env-based config

---

## 8. Dashboard

* Overall Risk Score + classification · scans · total findings · Critical/High/Medium/Low
* Charts: findings by **severity**, **provider**, **rule**
* Recent scans · scan selector · **“Why this score?”** tables
* Finding cards: description, **evidence**, **remediation**
* Untrusted text is rendered as text — never as HTML

---

## 9. Testing & verification

* **299 automated tests — 299 passed, 0 failed, 0 skipped · 98 % coverage**
* Unit · parser · **every rule with safe + vulnerable fixtures (real engine, no mocks)** · scoring boundaries · API · persistence · integration · dashboard (Streamlit AppTest vs a live server) · concurrency
* Real execution: live API, real dashboard in a browser, Docker Compose stack with restart persistence
* `ruff` clean · `bandit` 0 issues · `pip-audit` no known vulnerabilities

---

## 10. Security considerations

* IaC is **data**: no `terraform`, no `eval`/`exec`/`subprocess` (enforced by a static test)
* YAML SafeLoader; python-object tags rejected · path traversal neutralised · size/type limits
* Uploads never written to disk or stored; no secrets; no cloud SDKs or credentials
* Adversarial suite: traversal, YAML bombs, `local-exec`, SQLi, XSS, info leaks
* Residual risks documented: no auth/rate-limit, proxy-level size caps, CPU on pathological files

---

## 11. Demo / results

| Sample | Findings | Score | Level |
|---|---|---|---|
| `terraform/vulnerable.tf` | 10 | 100 | critical |
| `cloudformation/vulnerable.json` | 8 | 100 | critical |
| `cloudformation/vulnerable.yaml` | 3 | 70 | critical |
| `azure/vulnerable.tf` | 4 | 100 | critical |
| all four `safe.*` files | 0 | 0 | secure |

`make api` · `make dashboard` · `make seed` — or `docker compose up --build`

---

## 12. Future improvements

* Terraform modules / `locals` / `for_each` and plan-JSON input · ARM/Bicep
* More rules (IAM wildcards, CloudTrail, KMS, Key Vault) mapped to CIS/NIST
* SARIF export and PR-comment CI mode · suppressions with expiry · trend charts
* Authentication, per-team projects, PostgreSQL + Alembic
* Optional LLM-written *explanations* — never part of the score

---

# Thank you
**SentinelGuard AI** — static, explainable, safe by design.
