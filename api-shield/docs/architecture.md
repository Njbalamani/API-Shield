# APIShield architecture

| Field | Value |
| --- | --- |
| Version | 1.0.0 |
| Date | 24/11/2026 |
| Scope | Application layers, runtime topology, request flow, scanning flow, AI flow, monitoring flow, architecture decisions |

## 1. Layered architecture

APIShield is a modular Django monolith with clear boundaries between transport, middleware, application, domain, and persistence layers. The settings module composes twenty-four installed apps, including eleven project apps, a fixed middleware order, five DRF authentication classes, and a single SQL database connection that switches to in-memory SQLite under `TESTING=True`.

```mermaid
flowchart TB
    subgraph Presentation["Presentation layer"]
        Templates["Django templates"]
        Spa["REST clients"]
        Docs["DRF Spectacular schema and UI"]
    end

    subgraph Transport["Transport layer"]
        Wsgi["Gunicorn WSGI"]
        Asgi["ASGI entrypoint"]
        WhiteNoise["WhiteNoise staticfiles"]
    end

    subgraph CrossCutting["Cross-cutting middleware"]
        M1["SecurityMiddleware"]
        M2["WhiteNoiseMiddleware"]
        M3["SessionMiddleware"]
        M4["CorsMiddleware"]
        M5["CommonMiddleware"]
        M6["CsrfViewMiddleware"]
        M7["AuthenticationMiddleware"]
        M8["RequestIdMiddleware"]
        M9["OrganizationContextMiddleware"]
        M10["ApiBehaviourMonitorMiddleware"]
        M11["MessageMiddleware"]
        M12["XFrameOptionsMiddleware"]
    end

    subgraph Application["Application layer"]
        UrlConf["config.urls"]
        ApiConf["config.api"]
        Views["App views"]
        Viewsets["App DRF viewsets"]
        Services["Domain services"]
        Engines["Scan engines and rules"]
        Permissions["RBAC and tenant checks"]
        Reporting["Report builders"]
        ExceptionHandler["config.exception_handler"]
    end

    subgraph Domain["Domain layer"]
        DomainModels["Accounts, organizations, projects, endpoints"]
        ScanModels["Scans, findings, audits, alerts"]
        ResponseModels["Assignments, verifications, analyses, reports"]
    end

    subgraph Infrastructure["Infrastructure layer"]
        Database[(PostgreSQL or test SQLite)]
        Media[(MEDIA_ROOT)]
        Cacheless["No required cache"]
        Zap[(Optional OWASP ZAP)]
        Gemini[(Optional Google Gemini)]
    end

    Templates --> Wsgi
    Spa --> Wsgi
    Docs --> ApiConf
    Asgi --> UrlConf
    Wsgi --> M1
    M1 --> M2
    M2 --> M3
    M3 --> M4
    M4 --> M5
    M5 --> M6
    M6 --> M7
    M7 --> M8
    M8 --> M9
    M9 --> M10
    M10 --> M11
    M11 --> M12
    M12 --> UrlConf
    UrlConf --> Views
    UrlConf --> ApiConf
    ApiConf --> Viewsets
    ApiConf --> Docs
    Views --> Services
    Viewsets --> Services
    Services --> Permissions
    Services --> Engines
    Services --> Reporting
    Services --> DomainModels
    Services --> ScanModels
    Services --> ResponseModels
    Viewsets --> ExceptionHandler
    DomainModels --> Database
    ScanModels --> Database
    ResponseModels --> Database
    Reporting --> Media
    Engines --> Zap
    Services --> Gemini
```

### Layer responsibilities

| Layer | Owns | Does not own |
| --- | --- | --- |
| Presentation | Templates, REST payloads, schema UI | Authorization decisions, persistence rules |
| Transport | WSGI/ASGI, static file serving, process concurrency | Domain state |
| Middleware | Request IDs, tenant resolution, monitoring, security headers | Business workflows |
| Application | Routing, use cases, permissions, scan orchestration, reporting | Connection pooling details |
| Domain | Model invariants, relationships, status choices, constraint definitions | HTTP concerns |
| Infrastructure | PostgreSQL, media storage, optional external engines | Authorization policy |

## 2. Runtime topology

```mermaid
flowchart LR
    subgraph ClientNetwork["Client network"]
        Browser["Operator browser"]
        ApiClient["API client or CI job"]
        Scanner["Authorized ZAP controller"]
    end

    subgraph EdgeNetwork["Edge network"]
        Proxy["TLS reverse proxy"]
        Waf["Optional WAF"]
    end

    subgraph AppNetwork["Application network"]
        Web1["Gunicorn worker 1"]
        Web2["Gunicorn worker 2"]
        Web3["Gunicorn worker 3"]
        Static["WhiteNoise"]
    end

    subgraph DataNetwork["Private data network"]
        Postgres["PostgreSQL 16"]
        Media["apishield-media volume"]
        DbVolume["apishield-db volume"]
    end

    subgraph ToolNetwork["Isolated tooling network"]
        Zap["OWASP ZAP"]
    end

    Browser --> Proxy
    ApiClient --> Proxy
    Proxy --> Waf
    Waf --> Web1
    Waf --> Web2
    Waf --> Web3
    Web1 --> Static
    Web2 --> Static
    Web3 --> Static
    Web1 --> Postgres
    Web2 --> Postgres
    Web3 --> Postgres
    Web1 --> Media
    Web2 --> Media
    Web3 --> Media
    Postgres --> DbVolume
    Scanner --> Zap
    Web2 -->|only when allow_zap is enabled| Zap
```

### Process model

| Process | Responsibility | Scaling guidance |
| --- | --- | --- |
| Gunicorn worker | Serves Django WSGI requests | Default compose configuration uses three workers and a 120-second timeout |
| PostgreSQL | Stores all relational state | Use managed backups, connection limits, and TLS on the private network |
| WhiteNoise | Serves collected static assets from the web process | Collected at image build and container startup |
| OWASP ZAP | Optional active-testing engine | Keep isolated, never co-located with production data |
| CI runner | Runs lint, Django checks, migration check, tests | Uses `TESTING=True` and requires no external services |

## 3. Request flow

```mermaid
sequenceDiagram
    autonumber
    participant C as Browser or API client
    participant P as Reverse proxy
    participant S as Security and request-ID middleware
    participant A as Authentication middleware and DRF classes
    participant O as OrganizationContextMiddleware
    participant B as ApiBehaviourMonitorMiddleware
    participant V as View or DRF viewset
    participant R as RBAC permission classes
    participant M as Models and services
    participant E as Exception handler

    C->>P: HTTPS request
    P->>S: HTTP request with forwarded protocol
    S->>S: Apply host, CSRF, HSTS, frame, and request ID controls
    S->>A: Continue chain
    A->>A: Resolve session, token, JWT, OAuth2, or X-API-Key
    A->>O: Continue with request.user
    O->>O: Resolve active_organization_id and membership role
    O->>B: Continue with current_organization and current_role
    B->>B: Create ApiRequestLog where monitoring applies
    B->>V: Dispatch
    V->>R: Request required organization role
    alt authorized
        R-->>V: Allow
        V->>M: Query or mutate scoped data
        M-->>V: Result
        V-->>C: Response with X-Request-ID
    else denied
        R-->>E: PermissionDenied or NotAuthenticated
        E-->>C: Error envelope with code, message, details, request_id
    end
```

### Tenant resolution rules

| Situation | Result |
| --- | --- |
| Session contains a valid `active_organization_id` and active membership | That organization becomes `request.current_organization`; role comes from membership |
| Session organization is missing, inactive, or not a membership | First active organization by name is selected |
| API key authenticates | `request.current_organization` is set by `ApiKeyAuthentication` and inactive organizations are rejected |
| User has no active organization | `request.current_organization` remains `None`; member-only permissions deny access |
| User is superuser | RBAC helper allows the operation; organization context is still required by member permissions |

## 4. Scanning flow

```mermaid
flowchart TD
    A["Analyst creates project and ScanPolicy"] --> B["Owner confirms authorization and reference"]
    B --> C["Import OpenAPI specification"]
    C --> D["Create ApiEndpoint and EndpointParameter records"]
    D --> E["Request ScanRun"]
    E --> F{"mode"}
    F -->|passive| G["Read stored metadata only"]
    F -->|active| H{"ACTIVE_TESTING_ENABLED"}
    F -->|zap| I{"ALLOW_ZAP and policy allow_zap"}
    F -->|full| J["Evaluate passive then authorized active stages"]

    H -->|false| K["Downgrade to passive and append ScanLog"]
    H -->|true| L{"authorization_confirmed and reference present"}
    L -->|false| K
    L -->|true| M{"policy allow_active_tests"}
    M -->|false| K
    M -->|true| N{"host in allowed_hosts"}
    N -->|false| K
    N -->|true| O["Apply timeout, max_requests, rate_limit_rpm"]

    I -->|false| K
    I -->|true| N

    G --> P["Evaluate enabled ScanRule rows"]
    O --> P
    J --> P
    P --> Q["Create ScanFinding with verified=False"]
    Q --> R["Set severity, confidence, OWASP category, CWE, evidence, risk score"]
    R --> S["Update ScanRun counts, risk score, summary, finished_at"]
    S --> T["Analyst assigns finding and records VerificationRecord"]
```

### Scan safety gates

| Gate | Source | Failure behaviour |
| --- | --- | --- |
| Global active switch | `ACTIVE_TESTING_ENABLED` | Downgrade to passive |
| Owner confirmation | `ApiProject.authorization_confirmed` | Downgrade to passive |
| Authorization reference | `ApiProject.authorization_reference` | Downgrade to passive |
| Project active permission | `ScanPolicy.allow_active_tests` | Downgrade to passive |
| Host allowlist | `ScanPolicy.allowed_hosts` | Reject or downgrade |
| ZAP permission | `ALLOW_ZAP` and `ScanPolicy.allow_zap` | Downgrade or reject |
| Request limit | `MAX_ACTIVE_REQUESTS`, `ScanPolicy.max_requests` | Stop scanning at cap |
| Rate limit | `SCAN_RATE_LIMIT_RPM`, `ScanPolicy.rate_limit_rpm` | Throttle requests |
| Timeout | `SCAN_TIMEOUT_SECONDS`, `ScanPolicy.timeout_seconds` | Abort request and log |

## 5. AI flow

```mermaid
sequenceDiagram
    participant A as Analyst
    participant F as ScanFinding
    participant S as Analysis service
    participant C as Local risk model
    participant G as Google Gemini
    participant D as AiAnalysis
    participant R as Report builder

    A->>F: Open finding
    F->>S: Request explanation with severity, evidence, OWASP, CWE
    S->>S: Check AI_EXPLANATIONS_ENABLED
    alt external explanations disabled or no key
        S->>C: Compute local risk summary
        C-->>S: explanation, remediation, risk score, priority
        S->>D: Create or update with source=local
    else external explanations enabled
        S->>G: Send sanitized finding context
        G-->>S: explanation, remediation, optional code example
        S->>D: Create or update with source=gemini or hybrid
    end
    D-->>F: One-to-one analysis linked to finding
    F->>R: Include analysis in report
    R-->>A: PDF or JSON artifact
```

### AI data rules

| Rule | Implementation |
| --- | --- |
| Disabled by default | `AI_EXPLANATIONS_ENABLED=False` |
| Credential isolated | `GEMINI_API_KEY` only consumed when external source is enabled |
| Model configurable | `GEMINI_MODEL` defaults to `gemini-1.5-flash` |
| Local fallback | `AiAnalysis.Source.LOCAL` and default `model_name=local-risk-model` |
| Finding linkage | `AiAnalysis.finding` is a one-to-one relation |
| Human review preserved | AI output never sets `ScanFinding.verified=True` |

## 6. Monitoring flow

```mermaid
flowchart TD
    A["Request enters middleware chain"] --> B["ApiBehaviourMonitorMiddleware"]
    B --> C["Create ApiRequestLog with organization, project, method, path, IP, status, timing, query keys"]
    C --> D["Read BEHAVIOUR_WINDOW_MINUTES"]
    D --> E["Count requests by project and IP in window"]
    D --> F["Count failed responses in window"]
    D --> G["Match SENSITIVE_PATH_TERMS against path"]
    E --> H{"count >= REQUEST_FREQUENCY_THRESHOLD"}
    F --> I{"failures >= FAILED_REQUEST_THRESHOLD"}
    G --> J{"sensitive term present"}
    H -->|yes| K["Create BehaviourAlert high_frequency"]
    I -->|yes| L["Create BehaviourAlert repeated_failures"]
    J -->|yes| M["Create BehaviourAlert sensitive_endpoint"]
    H -->|no| N["No alert"]
    I -->|no| N
    J -->|no| N
    K --> O["analyst review and status transition"]
    L --> O
    M --> O
```

### Monitoring data model

| Signal | Stored field | Alert type |
| --- | --- | --- |
| Request count in window | `ApiRequestLog.timestamp` | `high_frequency` |
| Repeated failures | `ApiRequestLog.status_code` | `repeated_failures` |
| Sensitive path access | `ApiRequestLog.path` | `sensitive_endpoint` |
| Novel combination of IP, path, and query keys | `ip_address`, `path`, `query_keys` | `unusual_pattern` |

## 7. Architecture decision table

| Decision | Alternatives considered | Rationale | Trade-off |
| --- | --- | --- | --- |
| Modular Django monolith | Separate microservices per app | Shared tenant model, transactions, and simpler deployment | Workers scale as a unit |
| Custom `User` with email login | Username-based default user | Email is the platform identity and appears in audit trails | Requires `AUTH_USER_MODEL` from first migration |
| Organization membership roles | Global roles only | Same person can be analyst in one tenant and viewer in another | Role checks require organization context |
| Five DRF authentication classes | Single token scheme | Supports browser, service tokens, JWT, OAuth2, and API keys | More authentication surface to test |
| SHA-256 API key digest | Plaintext storage or reversible encryption | Raw key is shown once; stored value is not usable as a credential | Digest requires exact key normalization |
| PostgreSQL in production, SQLite in tests | SQLite everywhere | Production constraints and JSON behaviour match deployment; tests stay fast | Test and production engines differ |
| Passive scan default | Active scan default | Prevents accidental traffic to unauthorized systems | Active coverage needs explicit setup |
| Double-gated ZAP | Direct ZAP calls from any analyst | Global and per-project controls reduce misuse | More configuration steps |
| Findings start unverified | Auto-accept scanner output | Scanner rules can produce false positives | Requires human triage |
| OpenAPI as inventory source | Manual endpoint entry only | Fast, standardized, reproducible discovery | Depends on specification accuracy |
| Local AI fallback | External AI only | Works without data sharing and credentials | Lower explanation depth |
| Request-ID context variable | No correlation ID | Correlates logs across workers and error envelopes | Middleware must always reset context |
| Uniform DRF error envelope | Framework default errors | Stable client contract and explicit request IDs | Custom handler must cover all exceptions |
| WhiteNoise static serving | Separate static server | Fewer moving parts in container deployment | Static assets served by each web worker |
| Volume-backed reports | Local ephemeral storage | Reports survive container recreation | Backup must include media volume |
