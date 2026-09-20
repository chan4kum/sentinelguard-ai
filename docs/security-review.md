# Security review of SentinelGuard AI itself

Performed by the **Security Review Agent** (read-only review; fixes made by the owning agents). Date: 2026-09-19.
Scope: the application as built — API, parsers, persistence, dashboard, container and CI configuration.

## Evidence gathered

| Check | Result |
|---|---|
| `pytest` (303 tests incl. 43 adversarial/security tests and 4 concurrency regression tests) | **303 passed**, 0 failed, 0 skipped; 98 % line coverage |
| `ruff check` incl. flake8-bandit (`S`) rules | clean |
| `bandit -r src` | **0 issues** (one Medium `yaml.load` finding was removed — see F-3) |
| `pip-audit` (installed dependency set) | **No known vulnerabilities found** |
| Static "no-exec" test (`eval(`, `exec(`, `subprocess`, `os.system`, `pickle`, `yaml.load(`, `shell=True`) | clean |
| Live API, live dashboard, container smoke tests | pass (details in the final report) |

## Findings

| ID | Area | Finding | Severity | Status |
|---|---|---|---|---|
| F-1 | File handling | Long filenames (≈130–1000 chars) were truncated **through the extension**, so a valid `.tf` upload was rejected with a misleading 415. | Low (correctness) | **Fixed** — truncation keeps the extension; regression test added |
| F-2 | Test quality | Two of my own tests had wrong expectations (a resource miscount, an index typo). | Info | **Fixed** in the tests; product code was correct |
| F-3 | YAML | Bandit B506 flagged `yaml.load(..., Loader=_CfnLoader)`. It was a false positive (loader subclasses `SafeLoader`, verified by test) but the pattern was removed anyway by driving the loader object directly. | Low | **Fixed** |
| F-4 | Upload DoS | Starlette spools multipart parts to temporary storage before the handler can apply the per-file cap. The `Content-Length` pre-check (≈10.25 MB with defaults) blocks honest oversize requests, but chunked uploads without a length are not pre-checked. | Medium (deployment) | **Open / documented** — enforce request size and timeout at the reverse proxy |
| F-5 | Availability | Parsing is bounded by the 1 MiB per-file limit, but a pathological HCL/YAML document can still cost noticeable CPU; there is no per-request timeout. | Low–Medium | **Open / documented** |
| F-6 | AuthN/Z | The API has no authentication, authorisation or rate limiting; any caller who can reach it can create scans and read all results. | High if exposed, N/A locally | **Open / documented** — local/CI tool by design; put behind an authenticated proxy before exposing |
| F-7 | Detection accuracy | S3 policy detection falls back to a text heuristic when `jsonencode` bodies contain unresolved references (evidence is labelled `[text heuristic]`). Azure NSG priority is not evaluated. | Low (accuracy) | **Open / documented** |
| F-8 | Supply chain | Dependencies use lower bounds (no lockfile); the Docker base image is a tag, not a digest. | Low | **Open** — recommend a lockfile + digest pinning + scheduled `pip-audit` |
| F-9 | Concurrency / correctness | **Concurrent Terraform scans could silently lose findings.** `python-hcl2` serialises through a mutable `SerializationContext` created once as a default argument, shared by every thread. Forced with aggressive thread switching, 240 of 240 concurrent scans of a 10-finding file returned only 6–7 findings (a false-negative risk under load). Found because CI failed once (76 stored findings instead of 80); it did not reproduce locally in 30 runs. | Medium (correctness) | **Fixed** — HCL parsing is now serialised with a lock; deterministic regression tests (`tests/integration/test_concurrency.py`) fail without it and pass with it |

No critical or high finding is open for the intended local/CI use. F-6 becomes high the moment the service is exposed to an untrusted network.

## Review checklist (requested inspection areas)

| Area | Assessment | Evidence |
|---|---|---|
| Arbitrary code execution | **None possible via uploads.** Content is parsed as data; no dynamic evaluation anywhere. | static no-exec test; `local-exec` / `external` data-source fixtures produce no side effect (marker-file tests) |
| Shell / command execution | No `subprocess`/`os.system` in the app; monkeypatch test proves parsing never spawns a process. | `test_subprocess_is_not_available_to_parsers` |
| Unsafe Terraform processing | `terraform` is never invoked; only `python-hcl2` parses text. Modules/providers are never fetched. Interpolations such as `file("/etc/passwd")` stay unevaluated strings. | `test_terraform_interpolation_functions_are_not_evaluated` |
| YAML safety | `SafeLoader` subclass with CloudFormation short-form tags only; `!!python/object|name|module` rejected (422). Alias bombs are bounded (shared references, 1 MiB cap); deep nesting → 422. | `test_yaml_*` (5 payloads, bomb, depth) |
| Path traversal | Client filename → basename label, control chars stripped, length-capped; never used to build a path; no upload is ever written to disk by the application. | 5 traversal payloads assert no files created |
| File upload handling | Extension allow-list (415), per-file cap (413), `Content-Length` pre-check (413), max files (400), empty/NUL/non-UTF-8 (400). | ingest + API + security tests |
| Injection | SQLAlchemy bound parameters only; enum-validated filters; hostile names stored as inert text. | SQLi id/filter/resource-name tests |
| Secrets | No secrets in code, config or repo; `.env` ignored; DB stores findings, **not** uploaded content; no cloud SDKs or credentials. | secret-scan, `.env.example`, DB-bytes tests |
| Sensitive error messages | Single error envelope; parse errors name the file and line/column only; unexpected errors return a generic 500 with a `request_id`. | leak tests (no `Traceback`, paths, library names) |
| Dependency / configuration | Ranged deps, `pip-audit` clean today; settings validated with sane bounds; CORS not enabled; container runs as UID 10001. | pip-audit run; config tests; Dockerfile test |
| Database handling | Parameterised queries; FK cascade; WAL mode; sessions per operation; nothing sensitive persisted. | repository + persistence-restart tests |
| Dashboard / API trust boundary | Dashboard talks HTTP only, holds no logic, renders untrusted strings as text (`st.code`/`st.text`), never `unsafe_allow_html` with user data. | `test_dashboard_renders_hostile_resource_names_as_text` |
| No destructive cloud action | No AWS/Azure SDK, no credentials, no network calls other than dashboard → API; remediation is text only. | dependency + import test |

## Recommendations before any non-local deployment

1. Add authentication (API key/OIDC) and rate limiting; bind to localhost or a private network.
2. Enforce request-size and timeout limits at the proxy; consider a per-scan worker timeout.
3. Generate a lockfile, pin the base image by digest, and schedule `pip-audit` in CI.
4. Add Alembic migrations before the schema changes.
