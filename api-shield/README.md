# APIShield

| Field | Value |
| --- | --- |
| Product | APIShield — intelligent API security testing and threat detection platform |
| Version | 1.0.0 |
| Documentation date | 24/11/2026 |
| License | MIT |
| Runtime | Python 3.12, Django 5.1+, Django REST Framework, PostgreSQL 16 |
| Default web entrypoint | `http://localhost:8000` |
| API schema | `/api/schema/`, `/api/docs/`, `/api/redoc/` |

## Table of contents

| Section | Topic |
| --- | --- |
| [1](#1-product-overview) | Product overview |
| [2](#2-capability-matrix) | Capability matrix |
| [3](#3-architecture) | Architecture |
| [4](#4-workflows) | Workflows |
| [5](#5-folder-structure) | Folder structure |
| [6](#6-module-responsibilities) | Module responsibilities |
| [7](#7-environment-variables) | Environment variables |
| [8](#8-local-setup) | Local setup |
| [9](#9-docker-operations) | Docker operations |
| [10](#10-verification-commands) | Verification commands |
| [11](#11-rest-api-routes) | REST API routes |
| [12](#12-database-table-index) | Database table index |
| [13](#13-security-model) | Security model |
| [14](#14-scanning-authorization-rules) | Scanning authorization rules |
| [15](#15-owasp-api-top-10-mapping) | OWASP API Top 10 mapping |
| [16](#16-deployment-checklist) | Deployment checklist |
| [17](#17-documentation-index) | Documentation index |
| [18](#18-license) | License |

## Requirements summary

| Requirement | Implementation | Evidence |
| --- | --- | --- |
| Django MVT web application | Modular apps, templates, views, models, services | `config/urls.py` and `config/settings.py` |
| Django REST Framework API | Viewsets, serializers, exception handler, schema UI | `config/api.py` |
| PostgreSQL persistence | `DATABASE_URL` with PostgreSQL 16; SQLite only under `TESTING=True` | `config/settings.py` and `docs/deployment.md` |
| Custom CSS interface | `static/css/main.css` and custom JavaScript modules; no Bootstrap in project assets | [`static/`](static/) |
| Three.js and Chart.js visualization | `topology.js`, `charts.js`, dashboard and component templates | [`templates/dashboard/index.html`](templates/dashboard/index.html) |
| JWT, OAuth2, and API key authentication | Five DRF authentication classes and hashed API keys | [`accounts/authentication.py`](accounts/authentication.py) |
| OWASP ZAP integration | Optional ZAP adapter with global and per-project gates | [`api_scanner/engines/zap.py`](api_scanner/engines/zap.py) |
| OpenAPI parsing | JSON and YAML import into endpoint and parameter inventory | [`endpoint_discovery/services.py`](endpoint_discovery/services.py) |
| Real scanning functionality | Passive rules, controlled active tests, and ZAP adapter | [`api_scanner/`](api_scanner/) |
| AI explanations | Local scikit-learn scoring with optional Gemini explanations | [`ai_analysis/services.py`](ai_analysis/services.py) |
| Behaviour monitoring | Middleware-driven logs and anomaly alerts | [`behaviour_monitor/`](behaviour_monitor/) |
| Vulnerability management | Assignment, priority, verification, evidence, and status workflow | [`vulnerability_manager/`](vulnerability_manager/) |
| PDF and JSON reporting | ReportLab PDF builder and structured JSON reports | [`reports/services.py`](reports/services.py) |
| Secure uploads and API validation | Extension validation, 10 MB upload caps, organization scoping | `config.settings` and app serializers |
| Authorized active testing only | Global switch, project authorization, host allowlist, limits, and unverified findings | [`docs/scanning-authorization.md`](docs/scanning-authorization.md) |
| Structured documentation | Root and project READMEs with tables, diagrams, workflows, commands, and six detailed documents | [`docs/`](docs/) |
| MIT license with Njbalamani | Copyright (c) 2026 Njbalamani at repository root and project root | [`LICENSE`](LICENSE) |

## 1. Product overview

APIShield gives an organization one place to inventory APIs, import OpenAPI specifications, run passive analysis, run explicitly authorized active tests, audit authentication, monitor behavioural anomalies, triage vulnerabilities, request AI explanations, and export reports. Access is organization-scoped: every user belongs to an organization through an active `OrganizationMembership`, and every role check is resolved inside that organization boundary.

The platform separates observation from action. Passive analysis and dashboard metrics are derived from stored specifications, endpoints, scan runs, and findings. Active testing is a controlled operation that requires a confirmed owner, an explicit project flag, host allowlisting, and a rate-limited scan policy. Findings remain `verified=False` until a human records verification evidence.

| Design goal | Implementation |
| --- | --- |
| Tenant isolation | `Organization` foreign keys on projects, scans, audits, alerts, assignments, analyses, reports, logs, and API keys |
| Least privilege | Role ranks `viewer=1`, `developer=2`, `analyst=3`, `admin=4`; superuser bypass is explicit |
| Safe testing | `ACTIVE_TESTING_ENABLED`, `ScanPolicy.allow_active_tests`, authorization reference, allowlisted hosts, request caps, rate limits |
| Explainability | `ScanRule` metadata with OWASP/CWE/remediation, `AiAnalysis` linked one-to-one to a finding |
| Auditability | `LoginAttempt`, `ScanLog`, `ApiRequestLog`, `ApiKey.last_used_at`, request IDs on responses and logs |
| Portable delivery | Gunicorn container, WhiteNoise static assets, PostgreSQL via `DATABASE_URL`, in-memory SQLite when `TESTING=True` |

## 2. Capability matrix

### Platform capabilities

| Domain | Capability | Primary models |
| --- | --- | --- |
| Identity | Email-based user accounts, global roles, password validators, MFA flag | `accounts.User` |
| Access | Login attempt history, hashed API keys, DRF auth classes | `accounts.LoginAttempt`, `accounts.ApiKey` |
| Tenancy | Organizations, active memberships, organization switching | `organizations.Organization`, `organizations.OrganizationMembership` |
| Inventory | Projects, environments, owner, authorization record, scan policy | `api_projects.ApiProject`, `api_projects.ScanPolicy` |
| Discovery | OpenAPI JSON/YAML/text import and endpoint inventory | `api_projects.OpenApiSpecification`, `endpoint_discovery.ApiEndpoint`, `endpoint_discovery.EndpointParameter` |
| Scanning | Rule catalogue, scan runs, findings, scan logs | `api_scanner.ScanRule`, `api_scanner.ScanRun`, `api_scanner.ScanFinding`, `api_scanner.ScanLog` |
| Authentication | Token/OAuth2/API-key/basic audits and token tests | `authentication_audit.AuthenticationAudit`, `authentication_audit.TokenTest` |
| Monitoring | Request logs and behavioural alerts | `behaviour_monitor.ApiRequestLog`, `behaviour_monitor.BehaviourAlert` |
| Remediation | Assignment, priority, due date, verification records | `vulnerability_manager.VulnerabilityAssignment`, `vulnerability_manager.VerificationRecord` |
| Intelligence | Local, Gemini, or hybrid explanation records | `ai_analysis.AiAnalysis` |
| Reporting | PDF/JSON reports with type, format, status, stored artifact | `reports.Report` |
| Visibility | Dashboard metrics derived from database state | models across all apps |

### Scanning capability table

| Engine | Mode | Default state | Network behaviour |
| --- | --- | --- | --- |
| Custom passive rules | `passive` | Allowed by `ScanPolicy.allow_passive_tests=True` | Analysis of stored specification and endpoint metadata; no active probes |
| Custom active tests | `active` | Disabled by `ScanPolicy.allow_active_tests=False` and `ACTIVE_TESTING_ENABLED=False` | Only after authorization and allowlist gates pass |
| OWASP ZAP | `zap` | Disabled by `ScanPolicy.allow_zap=False`; global `ALLOW_ZAP=True` | Controlled ZAP instance at `ZAP_API_URL` with `ZAP_API_KEY` |
| Authentication audit | Rule engine `authentication` | Available through the audit module | Evaluates declared auth schemes and recorded token tests |
| Behaviour monitor | Rule engine `behaviour` | Middleware-driven | Records inbound APIShield traffic; no outbound scanning |
| Full assessment | `full` | Explicit opt-in | Combines allowed passive and authorized active stages |

### Role capability table

| Action | Viewer | Developer | Analyst | Admin |
| --- | --- | --- | --- | --- |
| View organization projects, endpoints, findings | Yes | Yes | Yes | Yes |
| Manage vulnerability fixes and assignments as assignee | No | Yes | Yes | Yes |
| Create projects, import specifications, run scans | No | No | Yes | Yes |
| Configure scan policies, approvals, reports, memberships | No | No | No | Yes |

## 3. Architecture

### Layered architecture

```mermaid
flowchart TB
    subgraph Clients["Clients"]
        Browser["Browser UI - Django templates"]
        ApiClient["REST clients - DRF"]
        Ci["CI and automation"]
    end

    subgraph Edge["Edge and platform services"]
        ReverseProxy["TLS reverse proxy"]
        Gunicorn["Gunicorn WSGI"]
        WhiteNoise["WhiteNoise static files"]
    end

    subgraph Middleware["Middleware chain"]
        Security["SecurityMiddleware"]
        RequestId["RequestIdMiddleware"]
        OrgContext["OrganizationContextMiddleware"]
        Behaviour["ApiBehaviourMonitorMiddleware"]
    end

    subgraph Application["Django application layer"]
        Urls["config.urls and config.api"]
        Views["App views"]
        Apis["App DRF viewsets"]
        Services["App services"]
        Permissions["accounts.permissions"]
        Rules["api_scanner engines and rules"]
    end

    subgraph Domain["Domain and persistence"]
        Models["22 application models"]
        Postgres["PostgreSQL - production"]
        Sqlite["In-memory SQLite - TESTING"]
        Media["MEDIA_ROOT - reports and uploads"]
    end

    subgraph External["Controlled integrations"]
        Zap["OWASP ZAP - optional"]
        Gemini["Google Gemini - optional"]
    end

    Browser --> ReverseProxy
    ApiClient --> ReverseProxy
    Ci --> ReverseProxy
    ReverseProxy --> Gunicorn
    Gunicorn --> WhiteNoise
    Gunicorn --> Security
    Security --> RequestId
    RequestId --> OrgContext
    OrgContext --> Behaviour
    Behaviour --> Urls
    Urls --> Views
    Urls --> Apis
    Views --> Services
    Apis --> Services
    Apis --> Permissions
    Views --> Permissions
    Services --> Rules
    Services --> Models
    Views --> Models
    Apis --> Models
    Models --> Postgres
    Models --> Sqlite
    Models --> Media
    Rules --> Zap
    Services --> Gemini
```

### Runtime topology

```mermaid
flowchart LR
    subgraph Internet["Public network"]
        User["Operator browser"]
    end

    subgraph DockerHost["Docker host"]
        Proxy["Reverse proxy - TLS termination"]
        Web["APIShield web container - 3 Gunicorn workers"]
        Db["PostgreSQL 16 container - apishield-db volume"]
        MediaVol["Shared media volume - apishield-media"]
        ZapContainer["Optional isolated ZAP container"]
    end

    User -->|HTTPS| Proxy
    Proxy -->|HTTP 8000| Web
    Web -->|DATABASE_URL| Db
    Web --> MediaVol
    Web -->|ZAP_API_URL only when enabled| ZapContainer
```

### Authentication and tenant resolution

```mermaid
sequenceDiagram
    participant Client as Client
    participant Middleware as Middleware chain
    participant Auth as DRF authentication classes
    participant Org as OrganizationContextMiddleware
    participant Perm as RBAC checks
    participant View as View or viewset

    Client->>Middleware: Request with session, JWT, token, OAuth2, or X-API-Key
    Middleware->>Middleware: Assign request_id and X-Request-ID
    Auth->>Auth: Resolve user or reject credentials
    Org->>Org: Resolve active_organization_id from session
    Org->>Org: Validate active membership and set current_role
    Client->>View: Resource request
    View->>Perm: has_minimum_role(user, organization, required_role)
    Perm-->>View: Allow or deny
    View-->>Client: Response with request_id and organization scope
```

## 4. Workflows

### Onboarding workflow

```mermaid
flowchart LR
    Register["User registration"] --> Membership["Create OrganizationMembership"]
    Membership --> Role["Assign admin, analyst, developer, or viewer"]
    Role --> Switch["Select active organization"]
    Switch --> Project["Create ApiProject and ScanPolicy"]
    Project --> Confirm["Record owner authorization reference"]
    Confirm --> Spec["Import OpenAPI JSON, YAML, or text"]
    Spec --> Endpoints["Create ApiEndpoint and EndpointParameter rows"]
```

### Scanning workflow

```mermaid
flowchart TD
    Start["Scan requested"] --> Requested{"Requested mode"}
    Requested -->|passive| Passive["Run passive rules on stored metadata"]
    Requested -->|active or zap| Gates{"Global flag, project authorization, policy flag, and host allowlist pass?"}
    Gates -->|no| Downgrade["Downgrade to passive and log the reason"]
    Gates -->|yes| Controlled["Apply max_requests, timeout, and rate_limit_rpm"]
    Controlled --> Engine["Run custom active tests or ZAP"]
    Passive --> Findings["Create ScanFinding rows with verified=False"]
    Engine --> Findings
    Downgrade --> Findings
    Findings --> Severity["Compute severity, OWASP category, CWE, and risk score"]
    Severity --> Review["Analyst review and assignment"]
    Review --> Verify["VerificationRecord with evidence"]
```

### Finding triage workflow

```mermaid
stateDiagram-v2
    [*] --> Open
    Open --> InProgress: assign VulnerabilityAssignment
    InProgress --> Fixed: engineer marks fixed
    Fixed --> VerifiedFixed: VerificationRecord result verified_fixed
    Fixed --> NotFixed: VerificationRecord result not_fixed
    NotFixed --> InProgress: reopen work
    VerifiedFixed --> Closed: close assignment
    Open --> FalsePositive: analyst rejects finding
    Open --> AcceptedRisk: owner accepts risk
    Closed --> [*]
```

### AI explanation workflow

```mermaid
flowchart LR
    Finding["ScanFinding"] --> Context["Title, severity, evidence, OWASP category, CWE"]
    Context --> Source{"AI_EXPLANATIONS_ENABLED and GEMINI_API_KEY"}
    Source -->|disabled| Local["Local risk model"]
    Source -->|enabled| Hybrid["Gemini or hybrid model"]
    Local --> Analysis["AiAnalysis linked one-to-one to finding"]
    Hybrid --> Analysis
    Analysis --> Report["Report and finding detail view"]
```

### Monitoring workflow

```mermaid
flowchart LR
    Request["Inbound APIShield request"] --> Log["ApiRequestLog created by middleware"]
    Log --> Window["Evaluate BEHAVIOUR_WINDOW_MINUTES"]
    Window --> Frequency{"count >= REQUEST_FREQUENCY_THRESHOLD"}
    Window --> Failures{"failed count >= FAILED_REQUEST_THRESHOLD"}
    Window --> Sensitive{"path contains SENSITIVE_PATH_TERMS"}
    Frequency --> Alert["BehaviourAlert with evidence"]
    Failures --> Alert
    Sensitive --> Alert
    Alert --> Status["open to acknowledged to resolved"]
```

## 5. Folder structure

```text
APIShield/
├── accounts/
│   ├── migrations/
│   ├── tests/
│   ├── admin.py
│   ├── api.py
│   ├── apps.py
│   ├── authentication.py
│   ├── forms.py
│   ├── logging_filters.py
│   ├── middleware.py
│   ├── models.py
│   ├── permissions.py
│   ├── serializers.py
│   ├── services.py
│   ├── urls.py
│   └── views.py
├── ai_analysis/
│   ├── migrations/
│   ├── tests/
│   ├── admin.py
│   ├── api.py
│   ├── apps.py
│   ├── forms.py
│   ├── models.py
│   ├── serializers.py
│   ├── services.py
│   ├── urls.py
│   └── views.py
├── api_projects/
│   ├── migrations/
│   ├── tests/
│   ├── admin.py
│   ├── api.py
│   ├── apps.py
│   ├── forms.py
│   ├── models.py
│   ├── serializers.py
│   ├── services.py
│   ├── urls.py
│   └── views.py
├── api_scanner/
│   ├── engines/
│   │   ├── base.py
│   │   ├── custom.py
│   │   └── zap.py
│   ├── management/commands/
│   │   ├── seed_demo_data.py
│   │   └── seed_rules.py
│   ├── migrations/
│   ├── tests/
│   ├── admin.py
│   ├── api.py
│   ├── apps.py
│   ├── forms.py
│   ├── models.py
│   ├── serializers.py
│   ├── services.py
│   ├── urls.py
│   └── views.py
├── authentication_audit/
│   ├── migrations/
│   ├── tests/
│   ├── admin.py
│   ├── api.py
│   ├── apps.py
│   ├── forms.py
│   ├── models.py
│   ├── serializers.py
│   ├── services.py
│   ├── urls.py
│   └── views.py
├── behaviour_monitor/
│   ├── migrations/
│   ├── tests/
│   ├── admin.py
│   ├── api.py
│   ├── apps.py
│   ├── forms.py
│   ├── middleware.py
│   ├── models.py
│   ├── serializers.py
│   ├── services.py
│   ├── urls.py
│   └── views.py
├── config/
│   ├── api.py
│   ├── asgi.py
│   ├── error_views.py
│   ├── exception_handler.py
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── dashboard/
│   ├── migrations/
│   ├── admin.py
│   ├── api.py
│   ├── apps.py
│   ├── forms.py
│   ├── models.py
│   ├── serializers.py
│   ├── services.py
│   ├── urls.py
│   └── views.py
├── docs/
│   ├── api.md
│   ├── architecture.md
│   ├── deployment.md
│   ├── er-diagram.md
│   ├── scanning-authorization.md
│   └── threat-model.md
├── endpoint_discovery/
│   ├── migrations/
│   ├── tests/
│   ├── admin.py
│   ├── api.py
│   ├── apps.py
│   ├── forms.py
│   ├── models.py
│   ├── serializers.py
│   ├── services.py
│   ├── urls.py
│   └── views.py
├── media/
│   └── reports/
├── organizations/
│   ├── migrations/
│   ├── tests/
│   ├── admin.py
│   ├── api.py
│   ├── apps.py
│   ├── context_processors.py
│   ├── forms.py
│   ├── middleware.py
│   ├── models.py
│   ├── serializers.py
│   ├── services.py
│   ├── urls.py
│   └── views.py
├── reports/
│   ├── migrations/
│   ├── tests/
│   ├── admin.py
│   ├── api.py
│   ├── apps.py
│   ├── forms.py
│   ├── models.py
│   ├── serializers.py
│   ├── services.py
│   ├── urls.py
│   └── views.py
├── static/
│   ├── css/
│   ├── js/
│   └── media/
├── templates/
│   ├── alerts/
│   ├── audits/
│   ├── auth/
│   ├── components/
│   ├── dashboard/
│   ├── endpoints/
│   ├── errors/
│   ├── findings/
│   ├── organizations/
│   ├── projects/
│   ├── reports/
│   ├── scans/
│   ├── vulnerabilities/
│   └── base.html
├── tests/
│   ├── __init__.py
│   └── test_platform.py
├── vulnerability_manager/
│   ├── migrations/
│   ├── tests/
│   ├── admin.py
│   ├── api.py
│   ├── apps.py
│   ├── forms.py
│   ├── models.py
│   ├── serializers.py
│   ├── services.py
│   ├── urls.py
│   └── views.py
├── .github/
│   └── workflows/
│       └── ci.yml
├── .dockerignore
├── .env.example
├── .gitignore
├── docker-compose.yml
├── Dockerfile
├── LICENSE
├── manage.py
├── pyproject.toml
├── README.md
└── requirements.txt
```

## 6. Module responsibilities

| Module | Responsibility |
| --- | --- |
| `config` | Settings, URL composition, API schema composition, ASGI/WSGI entrypoints, exception envelope, error views |
| `accounts` | Custom user, roles, login attempts, API keys, API-key authentication, request ID context, RBAC helpers |
| `organizations` | Organizations, memberships, active-organization middleware, template context flags |
| `api_projects` | Projects, OpenAPI specifications, scan policies, upload path generation |
| `endpoint_discovery` | Endpoints, methods, risk levels, security schemes, request/response schemas, parameters |
| `api_scanner` | Rule catalogue, scan runs, findings, scan logs, passive/active/ZAP engines |
| `authentication_audit` | Authentication audits and token tests |
| `behaviour_monitor` | Inbound request logs, anomaly detection, behaviour alerts, monitoring middleware |
| `vulnerability_manager` | Finding assignment, priority, due dates, and verification records |
| `ai_analysis` | Local, Gemini, or hybrid analysis records for findings |
| `reports` | PDF/JSON report records and stored artifacts |
| `dashboard` | Metrics and activity views derived from database state |
| `tests` | Cross-application integration suite executed with `TESTING=True` |
| `.github/workflows` | Continuous integration checks |

## 7. Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | `dev-only-insecure-secret-change-before-production` | Django signing key; production requires at least 50 characters |
| `DEBUG` | `True` | Debug mode, static storage selection, cookie security, HSTS |
| `TESTING` | `False` | Forces in-memory SQLite and disables persistent closes |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1` | Comma-separated Django host allowlist |
| `CSRF_TRUSTED_ORIGINS` | `http://localhost:8000` | Comma-separated CSRF origin allowlist |
| `CORS_ALLOWED_ORIGINS` | empty | Comma-separated browser origin allowlist |
| `DATABASE_URL` | `postgres://apishield:apishield@localhost:5432/apishield` | Parsed by `dj_database_url` |
| `ALLOW_PUBLIC_REGISTRATION` | `False` | Controls self-service account creation |
| `ACTIVE_TESTING_ENABLED` | `False` | Global kill switch for active scans |
| `ALLOW_ZAP` | `True` | Allows ZAP engine selection when the project policy also allows it |
| `ZAP_API_URL` | `http://127.0.0.1:8080` | Controlled ZAP API endpoint |
| `ZAP_API_KEY` | empty | ZAP API credential |
| `SCAN_TIMEOUT_SECONDS` | `15` | Default per-request scan timeout |
| `MAX_ACTIVE_REQUESTS` | `40` | Default maximum active requests |
| `SCAN_RATE_LIMIT_RPM` | `30` | Default scan request rate in requests per minute |
| `AI_EXPLANATIONS_ENABLED` | `False` | Enables external AI explanations |
| `GEMINI_API_KEY` | empty | Google Gemini credential |
| `GEMINI_MODEL` | `gemini-1.5-flash` | Gemini model identifier |
| `BEHAVIOUR_WINDOW_MINUTES` | `10` | Monitoring evaluation window |
| `FAILED_REQUEST_THRESHOLD` | `12` | Failed-request alert threshold |
| `REQUEST_FREQUENCY_THRESHOLD` | `120` | High-frequency alert threshold |
| `SENSITIVE_PATH_TERMS` | `admin,auth,token,password,secret,payment,billing,api-key` | Path terms that mark sensitive access |
| `DEMO_MODE` | `True` | Demo presentation behaviour |
| `JWT_ACCESS_TOKEN_LIFETIME_MINUTES` | `30` | JWT access token lifetime |
| `JWT_REFRESH_TOKEN_LIFETIME_DAYS` | `7` | JWT refresh token lifetime with rotation |
| `LOG_LEVEL` | `INFO` | Root and `apishield` logger level |

## 8. Local setup

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python manage.py check
python manage.py migrate
python manage.py seed_rules
python manage.py collectstatic --noinput
python manage.py createsuperuser
python manage.py runserver
```

On Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
$env:TESTING = "True"
python manage.py check
python manage.py migrate
python manage.py seed_rules
python manage.py collectstatic --noinput
python manage.py createsuperuser
python manage.py runserver
```

For automated tests, set `TESTING=True`; `config.settings` also enables test mode when `test` or `pytest` is in `sys.argv`. Test mode uses in-memory SQLite and never needs the production PostgreSQL service.

## 9. Docker operations

```bash
cp .env.example .env
docker compose build
docker compose up -d
docker compose ps
docker compose logs -f web
docker compose exec web python manage.py migrate
docker compose exec web python manage.py seed_rules
docker compose exec web python manage.py collectstatic --noinput
docker compose exec web python manage.py createsuperuser
docker compose restart web
docker compose down
docker compose down -v
```

The compose file starts PostgreSQL 16 with `apishield-db`, builds the web image with Gunicorn, mounts `.env` read-only, and persists reports/uploads in `apishield-media`. Set a production `DATABASE_URL`, a strong `SECRET_KEY`, and `DEBUG=False` before exposing the web service.

## 10. Verification commands

```bash
ruff check .
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py test
python manage.py test tests.test_platform -v 2
python manage.py spectacular --file schema.yml
```

Expected verification outcomes:

| Check | Expected result |
| --- | --- |
| `ruff check .` | No lint findings |
| `python manage.py check` | No system check errors |
| `makemigrations --check --dry-run` | No pending model changes |
| `python manage.py test` | All integration and application tests pass |
| `python manage.py spectacular --file schema.yml` | OpenAPI 3 schema generated |

## 11. REST API routes

The URL root is `/api/`. `config.api` mounts `/api/schema/`, `/api/docs/`, and `/api/redoc/`, then includes each application API module at the API root. Use `/api/schema/` as the live source of truth for final path names.

| Resource | Route | Typical methods |
| --- | --- | --- |
| Schema | `/api/schema/` | GET |
| Swagger UI | `/api/docs/` | GET |
| ReDoc | `/api/redoc/` | GET |
| Registration | `/api/accounts/register/` | POST |
| Login | `/api/accounts/login/` | POST |
| Current user | `/api/accounts/me/` | GET, PATCH |
| Account users | `/api/accounts/users/` | GET |
| Account user detail | `/api/accounts/users/{id}/` | GET |
| API keys | `/api/accounts/api-keys/` | GET, POST |
| API key detail | `/api/accounts/api-keys/{id}/` | GET, DELETE |
| API key revoke | `/api/accounts/api-keys/{id}/revoke/` | POST |
| Login attempts | `/api/accounts/login-attempts/` | GET |
| Login attempt detail | `/api/accounts/login-attempts/{id}/` | GET |
| Organizations | `/api/organizations/` | GET, POST |
| Organization detail | `/api/organizations/{id}/` | GET, PATCH, DELETE |
| Organization switch shortcut | `/api/organizations/switch/` | POST |
| Organization switch action | `/api/organizations/{id}/switch/` | POST |
| Organization members | `/api/organizations/{id}/members/` | GET |
| Add organization member | `/api/organizations/{id}/members/add/` | POST |
| Memberships | `/api/memberships/` | GET |
| Membership detail | `/api/memberships/{id}/` | GET |
| Projects | `/api/projects/` | GET, POST |
| Project detail | `/api/projects/{id}/` | GET, PATCH, DELETE |
| Project specification upload | `/api/projects/{id}/spec-upload/` | POST |
| Project authorization confirmation | `/api/projects/{id}/confirm-authorization/` | POST |
| Scan policies | `/api/scan-policies/{id}/` | GET, PATCH |
| Specifications | `/api/specifications/` | GET |
| Specification detail | `/api/specifications/{id}/` | GET |
| Endpoints | `/api/endpoints/` | GET |
| Endpoint detail | `/api/endpoints/{id}/` | GET |
| Endpoint discovery | `/api/endpoints/discover/` | POST |
| Endpoint parameters | `/api/endpoint-parameters/` | GET |
| Endpoint parameter detail | `/api/endpoint-parameters/{id}/` | GET |
| Scan runs | `/api/scans/` | GET |
| Scan start | `/api/scans/start/` | POST |
| Scan run detail | `/api/scans/{id}/` | GET |
| Scan logs | `/api/scans/{id}/logs/` | GET |
| Scan findings | `/api/findings/` | GET |
| Scan finding detail | `/api/findings/{id}/` | GET, PATCH |
| Scan rules | `/api/rules/` | GET |
| Authentication audits | `/api/auth-audits/` | GET |
| Authentication audit run | `/api/auth-audits/run/` | POST |
| Authentication audit detail | `/api/auth-audits/{id}/` | GET |
| Request logs | `/api/behaviour/logs/` | GET |
| Behaviour alerts | `/api/behaviour/alerts/` | GET |
| Behaviour alert detail | `/api/behaviour/alerts/{id}/` | GET |
| Behaviour alert action | `/api/behaviour/alerts/{id}/action/` | POST |
| Behaviour summary | `/api/behaviour/summary/` | GET |
| Vulnerability findings | `/api/vulnerability/findings/` | GET |
| Vulnerability finding detail | `/api/vulnerability/findings/{id}/` | GET |
| Finding assignment | `/api/vulnerability/findings/{id}/assign/` | POST |
| Finding verification | `/api/vulnerability/findings/{id}/verify/` | POST |
| Assignment history | `/api/vulnerability/findings/{id}/history/` | GET |
| Verification history | `/api/vulnerability/findings/{id}/verifications/` | GET |
| AI analyses | `/api/ai/` | GET |
| AI analysis run | `/api/ai/analyze/` | POST |
| AI analysis detail | `/api/ai/{id}/` | GET |
| Reports | `/api/reports/` | GET |
| Report generation | `/api/reports/generate/` | POST |
| Report types | `/api/reports/types/` | GET |
| Report detail | `/api/reports/{id}/` | GET |
| Report download | `/api/reports/{id}/download/` | GET |
| Dashboard metrics | `/api/dashboard/metrics/` | GET |
| Dashboard topology | `/api/dashboard/topology/` | GET |
| Dashboard summary | `/api/dashboard/summary/` | GET |

Authentication classes are evaluated in this order: session, DRF token, JWT bearer, OAuth2, and `X-API-Key`. Unauthenticated requests receive HTTP 401 or 403 depending on the selected authenticator. Viewer-role requests are denied on analyst and admin operations by `HasOrganizationRole` and `OrganizationRoleRequiredMixin`.

## 12. Database table index

| Model | Table | Purpose |
| --- | --- | --- |
| `accounts.User` | `accounts_user` | Custom email login identity, role, MFA flag, timestamps |
| `accounts.LoginAttempt` | `accounts_loginattempt` | Successful and failed login audit trail |
| `accounts.ApiKey` | `accounts_apikey` | Prefix, SHA-256 hash, activation, revocation, last use |
| `organizations.Organization` | `organizations_organization` | Tenant root record |
| `organizations.OrganizationMembership` | `organizations_organizationmembership` | User-to-tenant role assignment |
| `api_projects.ApiProject` | `api_projects_apiproject` | Target API, environment, owner, authorization record |
| `api_projects.OpenApiSpecification` | `api_projects_openapispecification` | Uploaded, pasted, or remote specification payload and parsed data |
| `api_projects.ScanPolicy` | `api_projects_scanpolicy` | Per-project testing permissions, allowlist, and limits |
| `endpoint_discovery.ApiEndpoint` | `endpoint_discovery_apiendpoint` | Method, path, schemas, security, risk level |
| `endpoint_discovery.EndpointParameter` | `endpoint_discovery_endpointparameter` | Parameter location, schema, example, sensitivity |
| `api_scanner.ScanRule` | `api_scanner_scanrule` | Rule metadata, severity, OWASP, CWE, remediation |
| `api_scanner.ScanRun` | `api_scanner_scanrun` | Scan lifecycle, mode, counts, risk score, authorization flag |
| `api_scanner.ScanFinding` | `api_scanner_scanfinding` | Finding evidence, severity, status, verification state |
| `api_scanner.ScanLog` | `api_scanner_scanlog` | Structured scan events and context |
| `authentication_audit.AuthenticationAudit` | `authentication_audit_authenticationaudit` | Auth type, result, checks, score |
| `authentication_audit.TokenTest` | `authentication_audit_tokentest` | Individual token test outcome and evidence |
| `behaviour_monitor.ApiRequestLog` | `behaviour_monitor_apirequestlog` | Method, path, status, timing, suspicion flag |
| `behaviour_monitor.BehaviourAlert` | `behaviour_monitor_behaviouralert` | Anomaly type, severity, evidence, lifecycle status |
| `vulnerability_manager.VulnerabilityAssignment` | `vulnerability_manager_vulnerabilityassignment` | Assignee, priority, due date, status |
| `vulnerability_manager.VerificationRecord` | `vulnerability_manager_verificationrecord` | Verification result, notes, evidence |
| `ai_analysis.AiAnalysis` | `ai_analysis_aianalysis` | Explanation, remediation, code example, model, source |
| `reports.Report` | `reports_report` | Report type, format, status, stored artifact |

## 13. Security model

| Control | Implementation | Evidence |
| --- | --- | --- |
| Password strength | `UserAttributeSimilarityValidator`, 12-character minimum, common-password and numeric validators | `AUTH_PASSWORD_VALIDATORS` |
| Session safety | `HttpOnly`, `SameSite=Lax`, secure cookies when `DEBUG=False` | Settings cookie flags |
| CSRF | `CsrfViewMiddleware`, trusted origins allowlist | Middleware and `CSRF_TRUSTED_ORIGINS` |
| Browser isolation | `X_FRAME_OPTIONS=DENY`, content-type sniffing off, browser XSS filter on | Security settings |
| Transport | HSTS for one year, subdomains and preload when `DEBUG=False` | `SECURE_HSTS_*` |
| Host validation | `ALLOWED_HOSTS`, `SECURE_PROXY_SSL_HEADER` | Settings |
| Cross-origin access | `CORS_ALLOWED_ORIGINS` default deny list | `corsheaders` |
| Authentication | Session, DRF token, rotating JWT, OAuth2, hashed API key | `REST_FRAMEWORK`, `SIMPLE_JWT`, `ApiKeyAuthentication` |
| API key storage | Raw key shown only on creation; SHA-256 digest stored; revocation and last-used tracked | `ApiKey.create_key`, `ApiKey.hash_key` |
| Authorization | Organization membership required; role rank comparison; superuser bypass explicit | `accounts.permissions` |
| Request correlation | `X-Request-ID` header and `request_id` log filter | `RequestIdMiddleware`, `RequestIdFilter` |
| Error safety | Uniform error envelope without stack traces in responses | `config.exception_handler` |
| Upload safety | Extension validator and 10 MB upload caps | `FileExtensionValidator`, settings |
| Monitoring | Request logs and alert evidence scoped to organization and project | `ApiRequestLog`, `BehaviourAlert` |

## 14. Scanning authorization rules

| Rule | Enforcement |
| --- | --- |
| Active tests require owner authorization | `ApiProject.authorization_confirmed=True` and a recorded `authorization_reference` |
| Controlled labs first | `ApiProject.Environment.CONTROLLED_LAB` is the default environment |
| Passive is the default | `ScanRun.Mode.PASSIVE` and `ScanPolicy.allow_passive_tests=True` |
| Active is opt-in per project | `ScanPolicy.allow_active_tests=False` by default |
| Global kill switch | `ACTIVE_TESTING_ENABLED=False` by default |
| ZAP is double-gated | `ALLOW_ZAP` and `ScanPolicy.allow_zap` must both be true |
| Host allowlisting | `ScanPolicy.allowed_hosts` contains explicitly approved hosts only |
| Rate limits | `SCAN_RATE_LIMIT_RPM`, `ScanPolicy.rate_limit_rpm`, and `MAX_ACTIVE_REQUESTS` |
| Timeouts | `SCAN_TIMEOUT_SECONDS` and `ScanPolicy.timeout_seconds` |
| No third-party scanning | Targets must be owned or contractually authorized; never scan public systems owned by others |
| No destructive payloads | No delete, wipe, privilege escalation, data modification, or denial-of-service payloads |
| Findings are untrusted until reviewed | `ScanFinding.verified=False` on creation; verification requires evidence |
| ZAP safety | Use an isolated ZAP instance, non-destructive policies, low throughput, and approved contexts only |

See [scanning-authorization.md](docs/scanning-authorization.md) for the full approval checklist and incident response guidance.

## 15. OWASP API Top 10 mapping

| OWASP category | APIShield coverage | Primary evidence |
| --- | --- | --- |
| API1 Broken Object Level Authorization | Organization-scoped foreign keys, membership checks, role mixins | `accounts.permissions`, project scans and audits |
| API2 Broken Authentication | Auth audits, password validators, JWT rotation, API key hashing, MFA flag | `AuthenticationAudit`, `TokenTest`, `ApiKey` |
| API3 Broken Object Property Level Authorization | Parameter sensitivity flags, schema inventory, endpoint risk levels | `EndpointParameter`, `ApiEndpoint` |
| API4 Unrestricted Resource Consumption | Request caps, rate limits, timeouts, monitoring thresholds | `ScanPolicy`, `ApiRequestLog`, `BehaviourAlert` |
| API5 Broken Function Level Authorization | Role ranks and viewer denial on analyst/admin operations | `HasOrganizationRole`, `IsAdminRole`, `IsAnalystRole` |
| API6 Unrestricted Access to Sensitive Business Flows | Sensitive path terms, behaviour alerts, authorization gates | `SENSITIVE_PATH_TERMS`, `BehaviourAlert` |
| API7 Server Side Request Forgery | Specification URL and active target host allowlisting | `OpenApiSpecification.source_url`, `ScanPolicy.allowed_hosts` |
| API8 Security Misconfiguration | Secure defaults, host/CSRF/CORS allowlists, HSTS, schema generation | `config.settings`, `/api/schema/` |
| API9 Improper Inventory Management | OpenAPI imports, endpoint/parameter inventory, scan rules, reports | `OpenApiSpecification`, `ApiEndpoint`, `ScanRule` |
| API10 Unsafe Consumption of APIs | File extension validation, upload caps, raw specification retention, optional AI isolation | `OpenApiSpecification`, settings limits, `AiAnalysis.source` |

## 16. Deployment checklist

| Item | Check |
| --- | --- |
| Secret | Unique `SECRET_KEY` of at least 50 characters |
| Debug | `DEBUG=False` |
| Registration | `ALLOW_PUBLIC_REGISTRATION` set to the intended value |
| Database | PostgreSQL reachable through `DATABASE_URL`; credentials protected |
| Migrations | `python manage.py migrate` completed |
| Rules | `python manage.py seed_rules` completed |
| Static files | `python manage.py collectstatic --noinput` completed |
| Hosts | `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`, and `CORS_ALLOWED_ORIGINS` set |
| TLS | HTTPS terminated at the reverse proxy; secure cookies and HSTS verified |
| Active testing | `ACTIVE_TESTING_ENABLED=False` unless an approved engagement is active |
| ZAP | Isolated instance, `ZAP_API_KEY` secret, approved contexts only |
| AI | `AI_EXPLANATIONS_ENABLED=False` unless data-sharing review is complete |
| Backups | PostgreSQL and `apishield-media` backup jobs scheduled and restored in a drill |
| Observability | `LOG_LEVEL`, request IDs, and alert routing confirmed |
| CI | `ruff check .`, `manage.py check`, migration check, and tests passing |

## 17. Documentation index

| Document | Purpose |
| --- | --- |
| [README.md](README.md) | Product overview, setup, verification, routes, security, deployment |
| [docs/architecture.md](docs/architecture.md) | Layers, runtime topology, request, scan, AI, and monitoring flows |
| [docs/er-diagram.md](docs/er-diagram.md) | Mermaid ER diagram and column-level model reference |
| [docs/api.md](docs/api.md) | REST endpoints, authentication, errors, pagination, throttling, examples |
| [docs/deployment.md](docs/deployment.md) | Local, Docker, production, PostgreSQL, TLS, backup, troubleshooting |
| [docs/scanning-authorization.md](docs/scanning-authorization.md) | Authorization and safe-testing controls |
| [docs/threat-model.md](docs/threat-model.md) | OWASP mapping, trust boundaries, threats, mitigations, residual risks |

## 18. License

APIShield is distributed under the MIT License. Copyright (c) 2026 Njbalamani. The software is provided "as is", without warranty of any kind. See [LICENSE](LICENSE) for the complete text.
