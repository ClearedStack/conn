# Conn specification

> Unified Command Portal, contractor-first tool catalog, pipeline item explorer, Muster SSE live-feed relay, and anonymous proof-of-work intake in the clearedstack namespace.

**Status: design, with a first build.** This is the specification for Conn (`v0.2.0-draft`, in the `conn` repository, formerly `clearedstack-web`). It describes how Conn works as the seventh control-plane workload in `clearedstack` and the sole public Ingress pod in the cluster.

## Overview and Role

Conn is the public bridge of the ClearedStack platform. Every other control-plane service and worker pod is strictly cluster-private behind default-deny `NetworkPolicy` rules. Conn alone terminates public web traffic and presents a read-only window into platform state alongside a hardened anonymous intake path:

- **Unified Command Portal (`GET /`):** Surfaces deterministic attention rules (`P0` degraded components or failed restore drills, `P1` stale SSE feed over 15 seconds or `needs_subtool` pauses, `P2` queue backlog), live queue lane depths (`urgent`, `normal`, `backfill`), a 17-component health grid, the latest backup restore drill, and recent pipeline activity.
- **Contractor-First Tool Catalog (`GET /tools/`, `GET /tools/{slug}`):** App Store style catalog with instant search (`?q=`) and status filtering (`live`, `linked`, `merged`, `retired`), provenance credit blocks, regulatory citations, and inline anonymous `Edit` proposal forms.
- **Pipeline Item Explorer (`GET /items/`, `GET /items/{id}`):** Transparent view of items across all 14 Contract v1 lifecycle states, including Assay evaluation gate and factor score breakdowns, Countersign owner decisions, and append-only state history.
- **17-Component Platform Registry (`GET /registry/`):** Displays all seven `clearedstack` control-plane services and all ten `cs-workers` stage workers with live sanitized health states and public error codes (`E_TIMEOUT`, `E_PARSE`, `E_NEEDS_SUBTOOL`).
- **Operational Guides (`GET /guides/`):** Publishes offline and disconnected-network operation procedures, clean-room boundary rules, and attribution and opt-out SLA commitments.
- **Live SSE Relay (`GET /v1/feed`):** Subscribes to Muster's `GET /v1/feed` stream in the background, tracks staleness (> 15 seconds without a `depths` frame raises a `P1` alert), and fans sanitized `depths`, `health`, and `edit` frames out to up to 64 concurrent browser subscribers so inline edit badges transition live (`Proposed -> Approved -> Building -> Live`).
- **Anonymous Proof-of-Work Intake (`POST /v1/edits`, `POST /v1/items`):** Validates payload size caps and `ownership_map.json` targets, extracts the visitor IP from `RemoteAddr` strictly in memory without logging or storing it, and forwards authenticated requests to Muster using Conn's Kubernetes ServiceAccount bearer token.

## Runtime and Resource Budget

| Attribute | Value |
| --- | --- |
| **Namespace** | `clearedstack` (Control Plane) |
| **Kind** | `control-plane` |
| **Version** | `v0.2.0-draft` |
| **Owning Repo** | `conn` (formerly `clearedstack-web`) |
| **RAM Request / Limit** | `64 MiB` request / `128 MiB` limit |
| **CPU Request / Limit** | `50m` request / `500m` limit |
| **Priority Class** | `clearedstack-high` (protected from node-pressure eviction) |
| **Architecture** | `linux/arm64` (excluding `cm3588-plus`) |
| **Storage** | Stateless (`readOnlyRootFilesystem: true`, zero persistent volumes) |
| **Network Exposure** | Sole public HTTPS `Ingress` -> `Service/conn` (`80 -> 8080`) |
| **Dependencies** | Go standard library only (zero external `go.mod` dependencies) |

## Interfaces and Data Contracts

| Peer / Caller | Direction | Protocol / Auth | Contract |
| --- | --- | --- | --- |
| **Public Browsers** | Inbound | HTTPS (`Ingress` -> TCP `8080`), zero cookies, zero login | HTML views, static CSS/JS, `GET /v1/feed` SSE, `POST /v1/edits` (<= 4 KiB), `POST /v1/items` (`site-form`, <= 64 KiB), `GET /healthz` |
| **Logbook** | Outbound | PostgreSQL 17 v3 wire protocol (`pub_ro` role, TCP `5432`) | Read-only Simple Query (`'Q'`) over `pub.*` views only; zero `core.*` access |
| **Muster** | Outbound | Cluster-private HTTP + SSE (`TCP 8080` / `80`, Kubernetes SA bearer token) | `GET /v1/feed`, `POST /v1/edits`, `POST /v1/items` (`site-form`), `GET /healthz` per Muster Contract v1 |

### Public Views Read from Logbook (`pub_ro`)

Conn connects to Logbook strictly as `pub_ro` over a pure-Go PostgreSQL v3 read-only wire client (`StartupMessage` v3.0, `AuthenticationOk`, `AuthenticationCleartextPassword`, `AuthenticationSASL` with `SCRAM-SHA-256`, and Simple Query `'Q'`) and reads only the twelve `pub.*` views:

1. `pub.catalog_entry` (`item_id`, `slug`, `status`, `title`, `summary`, `repository`, `link`, `merge`, `provenance`, `retirement`, `published_at`)
2. `pub.item` (`item_id`, `state`, `title`, `recorded_at`, `changed_at`)
3. `pub.item_history` (`entry_id`, `item_id`, `actor`, `from_state`, `to_state`, `error_code`, `note`, `recorded_at`)
4. `pub.evaluation` (`evaluation_id`, `item_id`, `profile`, `gates_passed`, `score`, `recommendation`, `split_flag`, `evaluated_at`)
5. `pub.evaluation_gate` (`evaluation_id`, `item_id`, `gate`, `passed`, `reason`)
6. `pub.evaluation_factor` (`evaluation_id`, `item_id`, `factor`, `rating`, `weight`, `points`)
7. `pub.decision` (`decision_id`, `item_id`, `evaluation_id`, `recommendation`, `outcome`, `overridden`, `reason`, `decided_at`)
8. `pub.queue_depth` (`worker`, `lane`, `waiting`, `claimed`)
9. `pub.pause` (`pause_id`, `item_id`, `worker`, `pattern`, `paused_at`, `replayed_at`)
10. `pub.edit_proposal` (`proposal_id`, `element_id`, `owner_repo`, `edit_class`, `status`, `payload`, `submitted_at`, `decided_at`)
11. `pub.restore_drill` (`drill_id`, `ran_at`, `passed`, `decrypt_passed`, `logbook_passed`, `plainforge_passed`, `lazarette_passed`)
12. `pub.component_health` (`component`, `state`, `error_code`, `reported_at`)

Conn never references `core.*` tables or functions. If `pub.catalog_entry` is not yet migrated or `42501` / `42P01` is returned, Conn degrades gracefully without crashing.

### Anonymous Intake and Browser Proof-of-Work

Both edit proposals (`POST /v1/edits`) and candidate tool suggestions (`POST /v1/items` with `source: "site-form"`) use Muster Contract v1's 20-bit SHA-256 puzzle:

```text
SHA-256("muster-pow-v1\x00" + day + "\x00" + a + "\x00" + b + "\x00" + c + "\x00" + nonce)
```

- `day` is today or yesterday in UTC (`YYYY-MM-DD`).
- `nonce` is 1 to 32 lowercase hexadecimal digits; the submitted `pow` token is `<day>.<nonce>`.
- For `POST /v1/edits`, `(a, b, c)` are `(target, change, reason)`. Conn enforces the 4,096-byte body limit and verifies `target` against `ownership_map.json` (`DATA`, `CONFIG`, `ISSUE`) before forwarding to Muster with `source` set from the visitor's `RemoteAddr` host.
- For `POST /v1/items`, `(a, b, c)` are `("site-form", title, address)`. Conn enforces the 65,536-byte body limit and forwards `source: "site-form"`, `title`, `address`, `pow`, and `visitor` (from `RemoteAddr`) to Muster.
- Browser JavaScript (`GET /static/app.js`) computes the 20-bit nonce via WebCrypto (`crypto.subtle.digest`) and listens on `EventSource('/v1/feed')` to transition submitted proposal badges through `Proposed` (`pending_approval`), `Approved` (`approved`), `Building` (`building`), and `Live` (`live`).

## Attention Rules and Failure Modes

| Priority | Condition | Portal Action |
| --- | --- | --- |
| **P0** | Any component in `degraded` state, latest restore drill failed, or Logbook read failed (`E_TIMEOUT`) | Red P0 alert banner at top of Command Portal naming only sanitized component slug and public error code |
| **P1** | More than 15 seconds elapsed since last Muster `depths` SSE frame (`stale`), or any active `needs_subtool` pause / `paused` component | Amber P1 alert banner highlighting stale live feed or paused subtool items |
| **P2** | Total waiting queue depth exceeds threshold or proposals await review in `pending_approval` | Informational P2 backlog notice |

- **Logbook Unreachable or Slow:** `pgwire` enforces strict connect and query deadlines and row/byte caps. Timeouts and connection errors map to public code `E_TIMEOUT`; pages render a clean degraded banner using cached feed state without panicking or leaking DSNs, IPs, hostnames, or credentials.
- **Muster Unreachable or Reconnecting:** `feedhub` reconnects to Muster's `GET /v1/feed` with bounded exponential backoff, preserves the last known snapshot, and flips staleness to `true` once 15 seconds pass without a `depths` event.
- **Slow Public SSE Clients:** Browser subscribers have bounded frame channels; any client whose buffer fills is disconnected cleanly so memory remains strictly within 128 MiB.

## Security and Clean-Room Boundaries

1. **Strict Response Headers on Every Route:**
   - `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'`
   - `X-Content-Type-Options: nosniff`
   - `Referrer-Policy: no-referrer`
2. **Zero Cookies, Zero Sessions, Zero IP Storage:** Conn sets no cookies, requires no login gates, and never logs or persists visitor IP addresses.
3. **Three Public Error Codes Only:** Every public error surfaces only `E_TIMEOUT`, `E_PARSE`, or `E_NEEDS_SUBTOOL` with fixed sanitized text.
4. **Hardened Pod Security and NetworkPolicy:** Non-root user `65532`, dropped `ALL` Linux capabilities, `RuntimeDefault` seccomp profile, read-only root filesystem, and default-deny `NetworkPolicy` permitting egress solely to CoreDNS (`53`), Logbook (`5432`), and Muster (`8080`, `80`).
