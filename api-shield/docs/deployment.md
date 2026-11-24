# APIShield deployment guide

| Field | Value |
| --- | --- |
| Version | 1.0.0 |
| Date | 24/11/2026 |
| Supported database | PostgreSQL 16 in production; in-memory SQLite under `TESTING=True` |
| Web server | Gunicorn WSGI, three workers in the supplied container |
| Static files | WhiteNoise |

## 1. Deployment modes

| Mode | Use case | Persistence | External services |
| --- | --- | --- | --- |
| Local development | Feature work and UI review | Local PostgreSQL or SQLite test mode | None required |
| Docker Compose | Single-host evaluation or controlled lab | Named volumes `apishield-db` and `apishield-media` | Optional ZAP |
| Production | Multi-user deployment behind TLS reverse proxy | Managed PostgreSQL and backed-up media storage | Optional ZAP and Gemini |

## 2. Local deployment

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python manage.py check
python manage.py migrate
python manage.py seed_rules
python manage.py collectstatic --noinput
python manage.py createsuperuser
python manage.py runserver
```

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python manage.py check
python manage.py migrate
python manage.py seed_rules
python manage.py collectstatic --noinput
python manage.py createsuperuser
python manage.py runserver
```

Local defaults assume PostgreSQL at `postgres://apishield:apishield@localhost:5432/apishield`. Create that database and role first, or set `DATABASE_URL` to a supported connection URL. Set `TESTING=True` only for automated tests; it replaces the configured database with in-memory SQLite.

## 3. Docker deployment

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
```

The supplied compose file:

- builds the image from `Dockerfile`;
- runs `migrate`, `seed_rules`, `collectstatic`, and Gunicorn in the web container;
- waits for the PostgreSQL health check before starting the web service;
- mounts `.env` read-only;
- persists the database in `apishield-db` and reports/uploads in `apishield-media`;
- publishes port `8000`.

Operational commands:

```bash
docker compose restart web
docker compose stop web
docker compose start web
docker compose down
docker compose down -v
docker compose exec db pg_isready -U apishield -d apishield
docker compose exec web python manage.py check
docker compose exec web python manage.py test
```

`docker compose down -v` deletes named volumes. Use it only when accepting permanent data loss.

## 4. PostgreSQL configuration

| Setting | Requirement |
| --- | --- |
| Version | PostgreSQL 16 or compatible |
| Database | Dedicated `apishield` database |
| Role | Dedicated role with ownership of tables and sequences |
| Connection | Set through `DATABASE_URL`; parse supports `postgres://` and `postgresql://` |
| SSL | Require TLS between application and database in production |
| Backups | Daily logical backups plus point-in-time recovery where available |
| Timezone | Store UTC; `USE_TZ=True` |
| Connection reuse | `CONN_MAX_AGE=600` outside test mode |

Example managed-service URL:

```text
DATABASE_URL=postgresql://apishield:<strong-password>@db.internal:5432/apishield?sslmode=require
```

Migration workflow:

```bash
python manage.py makemigrations --check --dry-run
python manage.py migrate --plan
python manage.py migrate
python manage.py showmigrations
```

Run migrations as a separate deployment step before starting new web workers. For zero-downtime rollout, use expand-and-contract schema changes and keep backwards-compatible views during the transition.

## 5. TLS and edge configuration

`config.settings` applies production security settings when `DEBUG=False`:

| Setting | Value |
| --- | --- |
| `SESSION_COOKIE_SECURE` | `True` |
| `CSRF_COOKIE_SECURE` | `True` |
| `SECURE_HSTS_SECONDS` | `31536000` |
| `SECURE_HSTS_INCLUDE_SUBDOMAINS` | `True` |
| `SECURE_HSTS_PRELOAD` | `True` |
| `SECURE_PROXY_SSL_HEADER` | `HTTP_X_FORWARDED_PROTO` |
| `X_FRAME_OPTIONS` | `DENY` |
| `SECURE_CONTENT_TYPE_NOSNIFF` | `True` |
| `SECURE_BROWSER_XSS_FILTER` | `True` |

Reverse-proxy requirements:

| Requirement | Reason |
| --- | --- |
| Terminate TLS before Gunicorn | Keeps application network simple |
| Set `X-Forwarded-Proto: https` | Enables Django secure URI and redirect detection |
| Preserve `X-Request-ID` | Maintains correlation across proxy and application |
| Forward `Authorization` and `X-API-Key` headers | Required by DRF authentication |
| Restrict body size | Complements 10 MB Django upload limits |
| Allow `/static/` and `/media/` routing | WhiteNoise serves static; media requires a protected route or object storage |

## 6. Environment configuration

Start from `.env.example` and change values per environment.

| Group | Variables |
| --- | --- |
| Core | `SECRET_KEY`, `DEBUG`, `TESTING`, `LOG_LEVEL` |
| Network | `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`, `CORS_ALLOWED_ORIGINS` |
| Data | `DATABASE_URL` |
| Identity | `ALLOW_PUBLIC_REGISTRATION`, `JWT_ACCESS_TOKEN_LIFETIME_MINUTES`, `JWT_REFRESH_TOKEN_LIFETIME_DAYS` |
| Scanning | `ACTIVE_TESTING_ENABLED`, `ALLOW_ZAP`, `ZAP_API_URL`, `ZAP_API_KEY`, `SCAN_TIMEOUT_SECONDS`, `MAX_ACTIVE_REQUESTS`, `SCAN_RATE_LIMIT_RPM` |
| AI | `AI_EXPLANATIONS_ENABLED`, `GEMINI_API_KEY`, `GEMINI_MODEL` |
| Monitoring | `BEHAVIOUR_WINDOW_MINUTES`, `FAILED_REQUEST_THRESHOLD`, `REQUEST_FREQUENCY_THRESHOLD`, `SENSITIVE_PATH_TERMS` |
| Product | `DEMO_MODE` |

Production baseline:

```text
DEBUG=False
TESTING=False
ALLOWED_HOSTS=apishield.example.internal
CSRF_TRUSTED_ORIGINS=https://apishield.example.internal
CORS_ALLOWED_ORIGINS=https://app.example.internal
ACTIVE_TESTING_ENABLED=False
AI_EXPLANATIONS_ENABLED=False
DEMO_MODE=False
LOG_LEVEL=INFO
```

Secret handling rules:

- Generate a unique `SECRET_KEY` of at least 50 characters; startup raises `RuntimeError` when production settings use a shorter key.
- Store `SECRET_KEY`, `ZAP_API_KEY`, `GEMINI_API_KEY`, and database credentials in a secret manager or restricted environment.
- Never commit `.env`, raw API keys, tokens, or report artifacts.
- Rotate API keys through `ApiKey` revocation and reissue, not by editing stored digests.

## 7. Static files and media

```bash
python manage.py collectstatic --noinput
```

| Path | Setting | Contents |
| --- | --- | --- |
| `static/` | `STATICFILES_DIRS` | Source CSS and JavaScript |
| `staticfiles/` | `STATIC_ROOT` | Collected assets served by WhiteNoise |
| `media/reports/` | `REPORTS_ROOT` | Generated PDF and JSON reports |
| `media/uploads/openapi/` | `SPECIFICATION_UPLOAD_ROOT` | Uploaded OpenAPI files |

Mount or back up the entire media tree. `Report.delete()` removes the file from storage when the row is deleted.

## 8. Backup and recovery

| Asset | Method | Frequency |
| --- | --- | --- |
| PostgreSQL | `pg_dump` or managed snapshots | Daily; more often during active engagements |
| Media volume | Volume snapshot or object-store sync | Daily |
| `.env` and secrets | Secret manager versioning | On change |
| OpenAPI specifications | Database plus media backup | Daily |
| Reports | Media backup with retention policy | Daily |

Backup command example:

```bash
pg_dump -h db.internal -U apishield -Fc apishield -f apishield.dump
docker compose exec web tar czf /tmp/apishield-media.tgz -C /app media
docker compose cp web:/tmp/apishield-media.tgz ./apishield-media.tgz
```

Restore procedure:

```bash
pg_restore -h db.internal -U apishield -d apishield -c apishield.dump
docker compose cp ./apishield-media.tgz web:/tmp/apishield-media.tgz
docker compose exec web tar xzf /tmp/apishield-media.tgz -C /app
python manage.py migrate
python manage.py check
python manage.py test
```

Run a restore drill before go-live and record recovery time objective and recovery point objective.

## 9. Observability

| Signal | Location |
| --- | --- |
| Application logs | Standard output through the `apishield` logger |
| Request ID | `X-Request-ID` response header and `%(request_id)s` log formatter |
| Login events | `accounts_loginattempt` |
| Scan events | `api_scanner_scanlog` |
| API-key usage | `accounts_apikey.last_used_at` |
| Behaviour anomalies | `behaviour_monitor_behaviouralert` |
| Errors | DRF error envelope with `error.request_id` |

Recommended alerts include sustained 500 responses, repeated failed logins, scan failures, unexpected active scan mode, behaviour alert spikes, and database connection saturation.

## 10. Troubleshooting

| Symptom | Likely cause | Resolution |
| --- | --- | --- |
| `SECRET_KEY must be at least 50 characters in production` | Debug disabled with default or short key | Set a unique long secret and restart |
| `Invalid host header` | `ALLOWED_HOSTS` does not include the request host | Add the exact host and restart |
| CSRF verification failed | Origin missing from `CSRF_TRUSTED_ORIGINS` | Add the HTTPS origin |
| Database connection refused | Wrong `DATABASE_URL` or database not ready | Verify URL, network, and health check |
| Static files return 404 | `collectstatic` not run or proxy path incorrect | Run collection and route `/static/` |
| API key rejected | Wrong key, inactive key, revoked key, inactive user, or inactive organization | Issue a new key and verify related flags |
| Viewer cannot run a scan | Role rank 1 below analyst rank 3 | Grant analyst membership |
| Active scan downgraded to passive | Authorization, policy, global switch, or host allowlist gate failed | Review `ScanPolicy` and `ScanLog` |
| ZAP scan fails | `ZAP_API_URL` unreachable or `ZAP_API_KEY` invalid | Check isolated ZAP service and credentials |
| Report generation fails | Media path not writable or disk full | Fix volume permissions and capacity |
| `makemigrations --check` fails | Model and migration state differ | Generate and review migrations in an allowed workspace |
| Tests use SQLite unexpectedly | `TESTING=True` or `test` in `sys.argv` | Expected behaviour; production remains PostgreSQL |
