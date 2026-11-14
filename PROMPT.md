# Build prompt: Conn

Open a new session on this repository and give it everything below the line.

---

You are building **Conn**, a control-plane service of the ClearedStack platform.

**What it is for:** Serves the unified Command Portal, contractor-first tool catalog, pipeline item explorer, live SSE status relay, and anonymous proof-of-work edit and candidate intake.

Read `SPEC.md` from start to finish before you do anything else. It is the specification. This prompt tells you how to work. Then read `component.json`, which is this component's entry in the naming registry.

## Where it sits

- **Namespace:** `clearedstack`
- **Depends on:** Logbook and Muster
- **Depended on by:** Public readers and operators over HTTPS Ingress

Its boundaries:

- Sole public HTTPS ingress pod in `clearedstack` (TCP `8080` behind `Service/conn` and `Ingress/conn`)
- Read-only SQL over Logbook's twelve `pub.*` views via the `pub_ro` role; zero access to `core.*`
- Subscribes to Muster's `GET /v1/feed` SSE stream with 15-second staleness (`P1`) detection and forwards anonymous `POST /v1/edits` and `POST /v1/items` (`site-form`) calls with a fresh Kubernetes ServiceAccount bearer token

## What to build

Everything `SPEC.md` describes, and nothing it does not. Where the specification gives a table of routes, views, attention rules, failure modes, or security headers, each row is a requirement.

## What does not exist yet

Conn depends on Logbook and Muster. Put Logbook reads behind a small `Reader` interface with an in-memory stand-in (`-standalone`) seeded with synthetic data, and put Muster behind a Contract v1 client and test stand-in so Conn runs and passes every test alone.

## Rules

1. **Language:** Go standard library ONLY (`module github.com/ClearedStack/conn` with zero `require` directives in `go.mod`). Implement the read-only PostgreSQL 17 v3 wire client (`SCRAM-SHA-256`, cleartext/trust auth, Simple Query `'Q'`) purely with the Go standard library.
2. **Clean room.** Write everything from scratch. Do not copy code, text, or structure from external projects.
3. **No AI when it runs.** Deterministic logic only. The same state produces the same output every time.
4. **Stop instead of guessing.** Validate requests strictly, enforce byte and row bounds, and refuse malformed inputs plainly.
5. **Every rule has a saved example.** Replay all 52 saved Muster Contract v1 examples with zero skips, and test every route, CSP header, PoW puzzle, SSE staleness transition, and `pgwire` protocol state.
6. **Small and unprivileged.** Run as non-root UID `65532` with a read-only root filesystem, all capabilities dropped, and within a `128 MiB` memory limit.
7. **No Docker.** Build straight from source with `ko` (`.ko.yaml`). Do not add a `Dockerfile`.
8. **Three public error codes.** `E_TIMEOUT`, `E_PARSE`, and `E_NEEDS_SUBTOOL`. Never leak DSNs, hostnames, internal IPs, file paths, or credentials in any error or HTTP response, and never log or store visitor IP addresses.
9. **Made-up data only.** Synthetic data only across code, seed fixtures, tests, comments, and commit messages. No secrets in Git.
10. **Zero em dashes.** Do not place the character `U+2014` anywhere in the repository.
11. **MIT license.** Keep the `LICENSE` file.
12. **Names come from the registry.** This component is `conn`. Follow `component.json` and Muster Contract v1 for every identifier.

## Done means

- `gofmt -l .` is empty, `go vet ./...` exits 0, `go test -race -count=1 ./...` passes 100%, and `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" ./cmd/conn` succeeds.
- All 52 Muster Contract v1 examples replay with zero skips.
- Deployment manifests (`deploy/conn.yaml`, `deploy/networkpolicy.yaml`, `deploy/ownership_map.json`, `.ko.yaml`, `app.yaml`) are tested by `deploy/deploy_test.go`.
- `README.md` documents what works today and how to run Conn in both `-standalone` and cluster modes.
