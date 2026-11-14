# Conn

Conn (formerly `clearedstack-web`) is the seventh control-plane workload in `clearedstack`. It serves as the sole public HTTPS entry pod for ClearedStack, combining:

1. **Command Portal (`GET /`)**: Deterministic `P0` / `P1` / `P2` attention alerts, live Muster lane depths (`urgent`, `normal`, `backfill`, `needs_subtool`), a 17-component health grid, latest backup restore drill verification, recent pipeline items, and anonymous tool suggestion intake.
2. **Contractor Tool Catalog (`GET /tools/`, `GET /tools/{slug}`)**: App Store directory for `live`, `linked`, `merged`, and `retired` contractor tools with search, status filters, authoritative rule citations, clean-room provenance notes, and inline anonymous `Edit` proposals.
3. **Pipeline Item Explorer (`GET /items/`, `GET /items/{id}`)**: Read-only visibility across all 14 Contract v1 item states, Assay screening gates and weighted rubric factors, Countersign review decisions, active `needs_subtool` pauses, and append-only item history.
4. **Platform Registry & Guides (`GET /registry/`, `GET /guides/`)**: Canonical inventory of all 17 platform workloads (`clearedstack` control-plane + `cs-workers` stage 1-10 workers) with sanitized public error codes (`E_TIMEOUT`, `E_PARSE`, `E_NEEDS_SUBTOOL`), offline operation architecture, clean-room boundary rules, and the 2-business-day attribution/opt-out SLA.
5. **Muster SSE Relay & Anonymous PoW Intake (`GET /v1/feed`, `POST /v1/edits`, `POST /v1/items`)**: Background subscription to Muster's `GET /v1/feed` stream with `>15s` staleness detection (`P1`), fan-out to up to 64 concurrent browsers, and 20-bit SHA-256 `muster-pow-v1` proof-of-work submission forwarding without cookies, user accounts, or visitor IP storage.

## Security & Dependency Boundaries

- **Go Standard Library Only**: `go.mod` declares `module github.com/ClearedStack/conn` with zero external module dependencies. PostgreSQL 17 wire protocol v3.0 (`SCRAM-SHA-256`, `StartupMessage`, Simple Query `'Q'`) is implemented directly over `net.Conn` and `crypto/tls` in `internal/pgwire`.
- **Read-Only `pub.*` Boundary**: Conn connects to Logbook as `pub_ro` and queries only the twelve security-barrier views (`pub.catalog_entry`, `pub.item`, `pub.item_history`, `pub.evaluation`, `pub.evaluation_gate`, `pub.evaluation_factor`, `pub.decision`, `pub.queue_depth`, `pub.pause`, `pub.edit_proposal`, `pub.restore_drill`, `pub.component_health`). It never references `core.*` tables.
- **Strict Content-Security-Policy**: Every HTTP response sets `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`, with zero cookies (`Set-Cookie` is never sent).
- **Zero Visitor IP Persistence**: On `POST /v1/edits` and `POST /v1/items`, Conn extracts the peer IP from `RemoteAddr` strictly in local stack memory to populate Muster's per-visitor salted daily HMAC check, and never logs, stores, or echoes the address.
- **128 MiB Non-Root Footprint**: Built with `ko` (`CGO_ENABLED=0`, `linux/arm64`) onto a digest-pinned static image in Lazarette, running as UID `65532` with `readOnlyRootFilesystem: true` and all Linux capabilities dropped.

## Running Standalone

Run Conn locally with synthetic seed data and an in-process Muster Contract v1 stand-in (no PostgreSQL or Kubernetes cluster required):

```bash
go run ./cmd/conn serve -standalone -listen 127.0.0.1:8080
```

Check version:

```bash
go run ./cmd/conn version
```

## Cluster Configuration

In `clearedstack` (`deploy/conn.yaml`), `conn serve` accepts flags or environment variables:

| Flag | Environment Variable | Purpose |
| --- | --- | --- |
| `-listen` | `CONN_LISTEN` | TCP listen address (default `:8080`) |
| `-standalone` | `CONN_STANDALONE` | Use in-memory synthetic `pub.*` store and Muster stand-in |
| `-database-url` | `CONN_DATABASE_URL` | Read-only PostgreSQL 17 DSN (`pub_ro` role) |
| `-database-password-file` | `CONN_DATABASE_PASSWORD_FILE` | Mounted `logbook-pub-credentials` password path |
| `-muster-url` | `MUSTER_URL` | Cluster-local Muster base URL |
| `-token-file` | `CONN_TOKEN_FILE` | Projected Kubernetes ServiceAccount token path |
| `-ownership-map` | `CONN_OWNERSHIP_MAP` | Mounted `ownership_map.json` path |

## Verification

```bash
gofmt -l .
go vet ./...
go test -race -count=1 ./...
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" ./cmd/conn
```
