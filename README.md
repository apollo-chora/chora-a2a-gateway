# chora-a2a-gateway

External Agent-to-Agent (A2A) gateway service for Chora per **ADR-132**. It
handles all inbound A2A traffic from registered partner agents: partner
registration, contract lifecycle, invocation, BYOA external-LLM keys, MCP
add-on config, and the federated account-closure saga.

The service is standalone and cloud-neutral: PostgreSQL repositories, a NATS
JetStream event bus, OTLP tracing via `OTEL_EXPORTER_OTLP_ENDPOINT`, and
env-backed configuration. No cloud account or managed services (managed SQL,
message broker, secret manager, or CI/CD) are required.

## Identity model — AGID is NOT GCID

Per CLAUDE.md §1 and ADR-132 §2: **AGID** (`AgentGlobalID`) is a distinct
identity class from human **GCID**. Agents CANNOT hold `TenantMembership`.
Every aggregate in this service (`Partner`, `Session`, `ExternalAgentIdentity`)
holds an `AGID` and **must never** carry a `gcid` field. The unit tests
assert this invariant by inspecting the JSON output for a `"gcid"` key.

## Endpoints

| Method | Path                                  | Description                                       |
|--------|---------------------------------------|---------------------------------------------------|
| GET    | `/healthz`                            | Liveness probe                                    |
| GET    | `/readyz`                             | Readiness probe                                   |
| POST   | `/a2a/v1/invoke`                      | Primary A2A entry. `X-AGID` required.             |
| GET    | `/a2a/v1/partners/{agid}`             | Fetch partner registry entry                      |
| POST   | `/a2a/v1/partners`                    | Register a partner (admin placeholder)            |
| GET    | `/a2a/v1/sessions/{correlation_id}`   | Fetch session log entry                           |
| POST   | `/partners/register`                  | Partner registration (partner-facing)             |
| GET    | `/contracts/`                         | Contract listing                                  |
| POST   | `/a2a/invoke`                         | Partner-facing invoke                             |
| GET    | `/api/v1/a2a/contracts`               | O+ A2A console contract listing (BFF)             |
| GET    | `/api/v1/a2a/identities`              | O+ A2A console identity listing (BFF)             |
| GET    | `/api/v1/a2a/invocations`             | O+ A2A console invocation listing (BFF)           |

Required headers on `/a2a/v1/*` endpoints:

- `X-AGID` — UUIDv7 of the calling partner agent (mandatory)
- `X-Correlation-Id` — UUIDv7 unique per call (mandatory on `/invoke`)

## Aggregates

| Aggregate                  | Holds | Lifecycle                                        |
|----------------------------|-------|--------------------------------------------------|
| `A2APartnerRegistry`       | AGID  | Active <-> Suspended; SoftDelete                 |
| `A2ASession`               | AGID  | **Append-only** — no UPDATE; new entry per call  |
| `ExternalAgentIdentity`    | AGID  | PEM + Ed25519 fingerprint; Rotate                |

## Rate limiting

In-memory **token-bucket per AGID**. Configured from each partner's
`rate_limit_per_minute`. Returns `429 RATE_LIMITED` when exhausted.

## Local stack

The service runs standalone with:

- **PostgreSQL** — `chora_a2a` database, durable outbox, and subscriber
  idempotency (migrations in `migrations/`)
- **NATS JetStream** — local event publishing and subscriptions

## Configuration

Create the local environment file:

```sh
cp .env.example .env
```

The checked-in `.env.example` contains the complete local defaults. The actual
`.env` file is ignored by Git.

Important variables:

| Variable | Purpose | Local default |
| --- | --- | --- |
| `PORT` | HTTP port | `8080` |
| `CHORA_DB_DSN` | PostgreSQL connection string (app_rw role) | Compose PostgreSQL |
| `CHORA_OUTBOX_DSN` | Durable outbox database | Same PostgreSQL instance |
| `NATS_URL` | NATS JetStream event bus | `nats://nats:4222` |
| `CHORA_SOURCE_PROJECT` | Source project label stamped on events | `chora-local` |
| `CHORA_A2A_REPO_BACKEND` | `unset`/`pg` (durable) or `inmem` (dev) | unset |
| `CHORA_PII_CLOSURE_MAP_PATH` | Per-domain closure PII map | `config/PII_Closure_Map.yaml` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/gRPC trace endpoint | `http://otel-collector:4317` |

## Run locally

From the repository root:

```sh
go run ./cmd/server
# in another shell
curl -s http://localhost:8080/healthz
curl -s -X POST http://localhost:8080/a2a/v1/invoke \
  -H 'Content-Type: application/json' \
  -H 'X-AGID: 01970000-0000-7000-b000-000000000001' \
  -H 'X-Correlation-Id: 01970000-0000-7000-c000-000000000001' \
  -d '{"action":"sample.echo","params":{"hello":"world"}}'
# Note: the bare local server has no seeded partners. The /invoke call
# above will return 404 PARTNER_NOT_FOUND until a partner is registered.
```

With the environment configured (`CHORA_DB_DSN`, `CHORA_OUTBOX_DSN`,
`NATS_URL`), the service wires the durable Postgres repositories, the
transactional outbox, and the NATS JetStream event bus. Unset, it falls back
to the in-memory adapters (dev mode).

## Database

PostgreSQL is the durable backing store (`chora_a2a`). The same database is
also used for the transactional outbox (`a2a_outbox_events`) and the closure
subscriber idempotency store (`closure_pseudonymisation_state`). Schema
changes live in `migrations/`.

The migrations are applied by the platform migration runner
(`scripts/migrate.sh` in the orchestrator repository), which mounts this
repository's `migrations/` directory. Every forward migration is a `*.sql`
file that is not a `*.down.sql`.

## Event bus

Local messaging uses NATS JetStream. The event taxonomy
(`chora.{domain}.{aggregate}.{event_type}.v{N}`) is unchanged, and the transport
is brokered by `github.com/apollo-chora/chora-common/eventbus`.

Two streams are provisioned: `CHORA_EVENTS` (subjects `chora.>`) and
`CHORA_DLQ` (subjects `_dlq.>`, the dead-letter convention). Consumers are
durable and created on demand by the service. If `NATS_URL` is unset the
application falls back to its in-memory event bus (publish-only; not durable).

## Tests

```sh
go test ./... -cover
```

Real-Postgres repository tests run under the `integration` build tag and are
skipped unless `CHORA_TEST_DSN` is set:

```sh
CHORA_TEST_DSN=postgres://chora:chora@localhost:5432/chora_a2a?sslmode=disable \
  go test -tags integration ./internal/adapter/repo/pg/...
```

## References

- `chora-contracts/openapi/a2a-gateway.yaml`
- `chora-contracts/proto/events/a2a/{contract,external_agent,invocation}.proto`
- CLAUDE.md §1 (AGID-vs-GCID), §3 (A2A as core domain)
