# APIShield REST API reference

| Field | Value |
| --- | --- |
| Version | 1.0.0 |
| Date | 24/11/2026 |
| Base URL | `http://localhost:8000/api/` |
| Schema | `GET /api/schema/` |
| Interactive docs | `GET /api/docs/`, `GET /api/redoc/` |
| Default page size | 25 |

## 1. Conventions

- Request and response bodies use `application/json` except report downloads, which use `application/pdf` or `application/json`.
- Collection endpoints use Django REST Framework page-number pagination.
- All non-public resources require authentication and an active organization membership.
- Organization scope for browser sessions comes from `active_organization_id`; API-key scope comes from the key record.
- Role names are `viewer`, `developer`, `analyst`, and `admin`, with ranks 1 through 4.
- Use `X-Request-ID` to supply a correlation identifier; the platform echoes it in the response header and error envelope.

## 2. Authentication methods

`REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]` is evaluated in this order:

| Method | Header or mechanism | Notes |
| --- | --- | --- |
| Session | Django session cookie | Used by template UI; CSRF required for unsafe methods |
| DRF token | `Authorization: Token <token>` | Backed by `rest_framework.authtoken` |
| JWT bearer | `Authorization: Bearer <access_token>` | 30-minute access lifetime, 7-day refresh lifetime, rotation enabled |
| OAuth 2.0 | OAuth2 toolkit token | Password flow token URL is `/oauth/token/` |
| API key | `X-API-Key: <raw_key>` | Raw key shown once; server stores a SHA-256 digest |

API-key authentication rejects inactive keys, revoked keys, inactive users, and inactive organizations. On success it sets `request.current_organization` and updates `ApiKey.last_used_at`.

```bash
curl -H "Authorization: Bearer <access_token>" \
  http://localhost:8000/api/projects/
```

```bash
curl -H "X-API-Key: apishield_xxxxxxxxxxxxxxxxxxxxxxxx" \
  http://localhost:8000/api/projects/
```

## 3. Endpoint catalogue

`config.urls` mounts the browser UI prefixes at `/accounts/`, `/organizations/`, `/projects/`, `/endpoints/`, `/scans/`, `/auth-audits/`, `/monitor/`, `/vulnerabilities/`, `/ai/`, `/reports/`, and `/dashboard/`. `config.api` mounts each application API module directly under `/api/`. The paths below mirror the installed `urlpatterns`; `/api/schema/` is the live source of truth.

### Identity and organizations

| Method | Path | Required role | Purpose |
| --- | --- | --- | --- |
| POST | `/api/accounts/register/` | Public when `ALLOW_PUBLIC_REGISTRATION=True` | Create user and initial owner membership |
| POST | `/api/accounts/login/` | Public | Authenticate and record `LoginAttempt` |
| GET, PATCH | `/api/accounts/me/` | Authenticated | Read or update current user |
| GET | `/api/accounts/users/` | Viewer | List organization users |
| GET | `/api/accounts/users/{id}/` | Viewer | Read an organization user |
| GET, POST | `/api/accounts/api-keys/` | Developer for writes | List or create API keys |
| GET, DELETE | `/api/accounts/api-keys/{id}/` | Developer | Read or revoke an API key |
| POST | `/api/accounts/api-keys/{id}/revoke/` | Developer | Revoke an API key |
| GET | `/api/accounts/login-attempts/` | Admin | Review authentication attempts |
| GET | `/api/accounts/login-attempts/{id}/` | Admin | Read an authentication attempt |
| GET, POST | `/api/organizations/` | Authenticated | List member organizations or create one |
| GET, PATCH, DELETE | `/api/organizations/{id}/` | Admin for writes | Manage an organization |
| POST | `/api/organizations/switch/` | Member | Set `active_organization_id` in session |
| POST | `/api/organizations/{id}/switch/` | Member | Router action for organization switching |
| GET | `/api/organizations/{id}/members/` | Viewer | List members |
| POST | `/api/organizations/{id}/members/add/` | Admin | Add a member |
| GET | `/api/memberships/` | Viewer | List memberships in the active organization |
| GET | `/api/memberships/{id}/` | Viewer | Read a membership |

### Projects, policies, specifications, and endpoints

| Method | Path | Required role | Purpose |
| --- | --- | --- | --- |
| GET, POST | `/api/projects/` | Analyst for writes | List or create API projects |
| GET, PATCH, DELETE | `/api/projects/{id}/` | Analyst for writes, Admin for delete | Manage a project |
| POST | `/api/projects/{id}/spec-upload/` | Analyst | Upload or paste an OpenAPI specification |
| POST | `/api/projects/{id}/confirm-authorization/` | Analyst | Record an authorization reference |
| GET, PATCH | `/api/scan-policies/{id}/` | Admin for writes | Read or update a scan policy |
| GET | `/api/specifications/` | Viewer | List imported specifications |
| GET | `/api/specifications/{id}/` | Viewer | Read an imported specification |
| GET | `/api/endpoints/` | Viewer | List discovered endpoints |
| GET | `/api/endpoints/{id}/` | Viewer | Read an endpoint |
| POST | `/api/endpoints/discover/` | Analyst | Rebuild endpoints from stored specifications |
| GET | `/api/endpoint-parameters/` | Viewer | List endpoint parameters |
| GET | `/api/endpoint-parameters/{id}/` | Viewer | Read an endpoint parameter |

### Scanning and authentication auditing

| Method | Path | Required role | Purpose |
| --- | --- | --- | --- |
| GET | `/api/scans/` | Viewer | List scan runs |
| POST | `/api/scans/start/` | Analyst | Create and execute a scan |
| GET | `/api/scans/{id}/` | Viewer | Inspect scan status and summary |
| GET | `/api/scans/{id}/logs/` | Viewer | Inspect scan log events |
| GET | `/api/findings/` | Viewer | List findings |
| GET, PATCH | `/api/findings/{id}/` | Analyst for PATCH | Inspect or update a finding |
| GET | `/api/rules/` | Viewer | List enabled scan rules |
| GET | `/api/auth-audits/` | Viewer | List authentication audits |
| POST | `/api/auth-audits/run/` | Analyst | Run an authentication audit |
| GET | `/api/auth-audits/{id}/` | Viewer | Inspect an authentication audit and token tests |

### Monitoring, remediation, AI, reports, and dashboard

| Method | Path | Required role | Purpose |
| --- | --- | --- | --- |
| GET | `/api/behaviour/logs/` | Analyst | Inspect `ApiRequestLog` rows |
| GET | `/api/behaviour/alerts/` | Analyst | Inspect behaviour alerts |
| GET | `/api/behaviour/alerts/{id}/` | Analyst | Inspect a behaviour alert |
| POST | `/api/behaviour/alerts/{id}/action/` | Analyst | Acknowledge or resolve an alert |
| GET | `/api/behaviour/summary/` | Analyst | Read behaviour counters |
| GET | `/api/vulnerability/findings/` | Developer | List findings for remediation |
| GET | `/api/vulnerability/findings/{id}/` | Developer | Read a finding |
| POST | `/api/vulnerability/findings/{id}/assign/` | Analyst | Assign a finding |
| POST | `/api/vulnerability/findings/{id}/verify/` | Analyst | Record verification evidence |
| GET | `/api/vulnerability/findings/{id}/history/` | Developer | Read assignment history |
| GET | `/api/vulnerability/findings/{id}/verifications/` | Developer | Read verification history |
| GET | `/api/ai/` | Viewer | List AI analyses |
| POST | `/api/ai/analyze/` | Analyst | Analyze a finding or scan |
| GET | `/api/ai/{id}/` | Viewer | Read an AI analysis |
| GET | `/api/reports/` | Analyst | List reports |
| POST | `/api/reports/generate/` | Analyst | Generate a PDF or JSON report |
| GET | `/api/reports/types/` | Viewer | List report and format choices |
| GET | `/api/reports/{id}/` | Analyst | Read report metadata |
| GET | `/api/reports/{id}/download/` | Viewer | Download the stored report artifact |
| GET | `/api/dashboard/metrics/` | Viewer | Read database-derived metrics |
| GET | `/api/dashboard/topology/` | Viewer | Read project and endpoint topology |
| GET | `/api/dashboard/summary/` | Viewer | Read metrics and topology together |

## 4. Error format

`config.exception_handler.api_exception_handler` wraps every handled DRF error and every unhandled exception in a stable envelope.

```json
{
  "error": {
    "code": "http_403",
    "message": "You do not have permission to perform this action.",
    "details": {
      "detail": "You do not have permission to perform this action."
    },
    "request_id": "6f0f1f2c9a3d4b0f9c0e1d2a3b4c5d6e"
  }
}
```

| Field | Description |
| --- | --- |
| `error.code` | `http_<status>` for handled errors; `internal_error` for unhandled exceptions |
| `error.message` | Human-readable summary extracted from `detail` |
| `error.details` | Original DRF error payload |
| `error.request_id` | Incoming `X-Request-ID` value or a generated UUID |

| Status | Meaning |
| --- | --- |
| 400 | Validation failure |
| 401 | Authentication credentials missing or invalid |
| 403 | Authenticated but role or organization permission denied |
| 404 | Resource not found in the current organization scope |
| 405 | Method not allowed |
| 429 | Throttled when throttling is configured |
| 500 | Unhandled server error |

## 5. Pagination

The default pagination class is `rest_framework.pagination.PageNumberPagination` with `PAGE_SIZE=25`.

```json
{
  "count": 84,
  "next": "http://localhost:8000/api/projects/?page=2",
  "previous": null,
  "results": []
}
```

Clients control pages with `?page=<number>`. Endpoint implementations may override the page size with `?page_size=<number>` when explicitly enabled.

## 6. Rate limiting

| Scope | Control | Default |
| --- | --- | --- |
| DRF API requests | `DEFAULT_THROTTLE_CLASSES` and `DEFAULT_THROTTLE_RATES` | Empty; no global throttle by default |
| Active scan traffic | `SCAN_RATE_LIMIT_RPM` and `ScanPolicy.rate_limit_rpm` | 30 requests per minute |
| Active scan volume | `MAX_ACTIVE_REQUESTS` and `ScanPolicy.max_requests` | 40 requests |
| Active scan latency | `SCAN_TIMEOUT_SECONDS` and `ScanPolicy.timeout_seconds` | 15 seconds |
| Behaviour alerting | `REQUEST_FREQUENCY_THRESHOLD` | 120 requests in the monitoring window |

Production deployments should add authenticated-user throttles and proxy-level rate limits; see [deployment.md](deployment.md).

## 7. Example requests

### Register and switch organization

```bash
curl -X POST http://localhost:8000/api/accounts/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "email":"analyst@example.test",
    "username":"analyst",
    "full_name":"API Analyst",
    "password":"a-very-long-password",
    "organization_name":"Example Lab",
    "organization_slug":"example-lab"
  }'
```

```bash
curl -X POST http://localhost:8000/api/organizations/2/switch/ \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

### Create a project and update its scan policy

```bash
curl -X POST http://localhost:8000/api/projects/ \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"Payments API",
    "slug":"payments-api",
    "environment":"controlled_lab",
    "base_url":"http://localhost:9000",
    "authorization_confirmed":false,
    "authorization_reference":""
  }'
```

```bash
curl -X PATCH http://localhost:8000/api/scan-policies/1/ \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"allow_passive_tests":true,"allow_active_tests":false,"allow_zap":false,"rate_limit_rpm":20}'
```

### Import an OpenAPI document

```bash
curl -X POST http://localhost:8000/api/projects/1/spec-upload/ \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"payments-openapi",
    "content":"{\"openapi\":\"3.0.3\",\"paths\":{}}"
  }'
```

### Request a passive scan

```bash
curl -X POST http://localhost:8000/api/scans/start/ \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"project":1,"specification":1,"mode":"passive"}'
```

### Inspect findings and assign remediation

```bash
curl http://localhost:8000/api/findings/ \
  -H "X-API-Key: apishield_xxxxxxxxxxxxxxxxxxxxxxxx"
```

```bash
curl -X POST http://localhost:8000/api/vulnerability/findings/12/assign/ \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"assignee":7,"priority":"high","due_date":"2026-12-15"}'
```

### Generate and download a report

```bash
curl -X POST http://localhost:8000/api/reports/generate/ \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"project":1,"scan_run":1,"report_type":"full","file_format":"pdf"}'
```

```bash
curl -O -J http://localhost:8000/api/reports/3/download/ \
  -H "Authorization: Bearer <access_token>"
```

## 8. Client guidance

| Guidance | Reason |
| --- | --- |
| Send `X-Request-ID` on every request | Correlates client logs with server logs |
| Treat findings as unverified until `verified=true` | Scanner output requires analyst confirmation |
| Never send production secrets in specification examples | Specifications and evidence are persisted |
| Use a dedicated API key per integration | Supports rotation and per-key revocation |
| Re-check `/api/schema/` after upgrades | Generated schema follows installed viewsets |
| Deny viewer roles on scan and policy writes | `HasOrganizationRole` enforces rank comparison |
