# chora-a2a-gateway

## About

`chora-a2a-gateway` is the standalone HTTP and gRPC gateway for Chora's external Agent-to-Agent (A2A) integration. It accepts partner registration and A2A invocation traffic, manages contracts, partner-agent identities, BYOA external-LLM keys, MCP add-on configuration, DNS verification, and related audit/listing operations. The service uses PostgreSQL-backed repositories, a transactional outbox with NATS JetStream delivery, and OTLP tracing, with in-memory adapters available for local development and tests.

## Quick start

Requires Go 1.26. The repository declares Go `1.26.1` in `go.mod`.

Clone the repository and start the server:

```sh
git clone https://github.com/apollo-chora/chora-a2a-gateway.git
cd chora-a2a-gateway

cp .env.example .env
go run ./cmd/server
```

For a local process-only run, leave the database and NATS settings unset and explicitly select the in-memory repository backend:

```sh
CHORA_A2A_REPO_BACKEND=inmem go run ./cmd/server
```

The server listens on `:8080` by default. Check the service from another shell:

```sh
curl -s http://localhost:8080/healthz
curl -s http://localhost:8080/readyz
```

The checked-in `.env.example` defines PostgreSQL as `chora_a2a`, NATS at `nats://nats:4222`, and the default PII closure map at `config/PII_Closure_Map.yaml`. The Dockerfile builds the service from the repository root and produces Linux `amd64` and `arm64` images in the repository's GitHub Actions workflow.

## Usage

The server exposes liveness and readiness endpoints, two REST surfaces, and read-only A2A listings.

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/healthz` | Liveness |
| `GET` | `/readyz` | Readiness |
| `POST` | `/a2a/v1/invoke` | Primary A2A invocation entry |
| `GET` | `/a2a/v1/partners/{agid}` | Look up a partner by AGID |
| `POST` | `/a2a/v1/partners` | Register a partner in the legacy A2A v1 surface |
| `GET` | `/a2a/v1/sessions/{correlation_id}` | Fetch a legacy invocation session |
| `POST` | `/partners/register` | Partner-facing registration |
| `GET` | `/partners/{id}` | Fetch a registration |
| `GET` | `/admin/partners?status=...` | List registrations by state |
| `POST` | `/admin/partners/{id}:approve` | Approve a partner and mint an AGID/API key |
| `POST` | `/admin/partners/{id}:suspend` | Suspend a partner |
| `POST` | `/admin/partners/{id}:reinstate` | Reinstate a partner |
| `POST` | `/admin/partners/{id}:revoke` | Revoke a partner |
| `POST` | `/contracts/{partner_id}` | Create a contract |
| `GET` | `/contracts/{partner_id}` | List a partner's contracts |
| `GET` | `/contracts/{partner_id}/openapi.yaml` | Get the contract's OpenAPI subset |
| `POST` | `/a2a/invoke` | Partner-facing invocation |
| `GET` | `/a2a/audit?partner_id=...` | Partner invocation audit |
| `POST` | `/admin/byoa/{tenant_id}/{provider}` | Store an encrypted external-LLM API key |
| `DELETE` | `/admin/byoa/{tenant_id}/{provider}` | Revoke a BYOA key |
| `POST` | `/admin/mcp/{tenant_id}` | Configure an MCP add-on |
| `GET` | `/admin/mcp/{tenant_id}` | Fetch MCP configuration |
| `POST` | `/admin/mcp/{tenant_id}:suspend` | Suspend an MCP add-on |
| `POST` | `/admin/mcp/{tenant_id}:reinstate` | Reinstate an MCP add-on |
| `POST` | `/admin/mcp/_resolve` | Resolve an MCP API key to its tenant |
| `POST` | `/admin/dns/verify` | Verify a partner domain's DNS TXT record |
| `GET` | `/api/v1/a2a/contracts` | Console contract listing |
| `GET` | `/api/v1/a2a/identities` | Console identity listing |
| `GET` | `/api/v1/a2a/invocations?since=...` | Console invocation listing |

Requests under `/a2a/v1/*` require the `X-AGID` header. The `/a2a/v1/invoke` endpoint also requires `X-Correlation-Id`. Both values are expected to use UUIDv7 identifiers.

A basic invocation looks like this:

```sh
curl -s -X POST http://localhost:8080/a2a/v1/invoke \
  -H 'Content-Type: application/json' \
  -H 'X-AGID: 01970000-0000-7000-b000-000000000001' \
  -H 'X-Correlation-Id: 01970000-0000-7000-c000-000000000001' \
  -d '{"action":"sample.echo","params":{"hello":"world"}}'
```

With the bare `go run` process there is no seeded partner, so this request returns `404 PARTNER_NOT_FOUND` until a matching partner is registered.

The partner-facing `/a2a/invoke` route uses `X-Partner-Id`, `X-API-Key`, and `X-Correlation-Id`. Contracts define capabilities, authentication methods, versions, and per-capability rate limits.

The rate limiter is an in-memory token bucket keyed by AGID. Built-in partner tiers configure default limits of `60`, `300`, `1200`, or `6000` requests per minute for `low`, `medium`, `high`, and `critical` tiers respectively. Requests that exhaust a bucket receive `429`.

Configuration is environment-backed:

| Variable | Purpose |
| --- | --- |
| `PORT` | HTTP listen port, default `8080` |
| `CHORA_DB_DSN` | PostgreSQL runtime DSN |
| `CHORA_OUTBOX_DSN` | PostgreSQL DSN for the transactional outbox |
| `CHORA_DB_DSN_SECRET_ID` | Secret-backed database DSN when a direct DSN is not supplied |
| `NATS_URL` | NATS JetStream URL |
| `CHORA_SOURCE_PROJECT` | Source project value stamped on emitted events |
| `CHORA_SOURCE_SERVICE` | Source service configuration |
| `CHORA_A2A_REPO_BACKEND` | Repository backend: durable PostgreSQL or explicit `inmem` development mode |
| `CHORA_A2A_REPO_TENANT_ID` | Tenant binding used by PostgreSQL A2A repositories |
| `CHORA_CLOSURE_SUBSCRIPTION` | Closure-saga consumer name |
| `CHORA_PII_CLOSURE_MAP_PATH` | Path to the PII closure map |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/gRPC endpoint |
| `CHORA_OUTBOX_WORKER_ID` | Outbox dispatcher worker ID |
| `CHORA_BOOTSTRAP_TIMEOUT_SECONDS` | Bootstrap timeout |
| `CHORA_DURABILITY_GUARD` | Durability guard mode, `report` or `enforce` |

PostgreSQL is the durable store for registrations, contracts, invocations, MCP configuration, BYOA credentials, agent identities, and closure/outbox state when the PostgreSQL backend is selected. Schema files are under `migrations/`.

Events are emitted through the `chora-common/eventbus` package. The producer-side transactional outbox is stored in `a2a_outbox_events` and dispatched to NATS JetStream. The configured event streams are `CHORA_EVENTS` for `chora.>` subjects and `CHORA_DLQ` for dead-letter subjects.

## Development

Build the server:

```sh
go build ./cmd/server
```

Run the complete unit test suite with coverage:

```sh
go test ./... -cover
```

Run the PostgreSQL integration tests with the `integration` build tag and `CHORA_TEST_DSN`:

```sh
CHORA_TEST_DSN='postgres://chora:chora@localhost:5432/chora_a2a?sslmode=disable' \
  go test -tags=integration ./internal/adapter/repo/pg/...
```

The main directories are:

```text
cmd/server/                 Service entry point and bootstrap
internal/adapter/           HTTP, gRPC, PostgreSQL, in-memory, DNS, events, outbox, and rate-limiter adapters
internal/config/            PII closure-map configuration loading
internal/domain/            Partner, contract, invocation, MCP, BYOA, identity, and session domain models
internal/observability/     OTLP and traceparent middleware
migrations/                 PostgreSQL schema migrations
config/                     PII_Closure_Map.yaml
Dockerfile                  Container build
```

The legacy `/a2a/v1/*` surface currently uses in-memory partner and session stores. The newer partner-facing registration, contract, invocation, MCP, BYOA, and identity repositories are selected during bootstrap according to `CHORA_A2A_REPO_BACKEND`; PostgreSQL is used when durable storage is configured, while `inmem` is an explicit development backend.
