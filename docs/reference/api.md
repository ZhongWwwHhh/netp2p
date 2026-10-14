# API contract

Base URL for each manager:

```text
https://manager-1.netp2p.example:9443/api/v1
```

The machine-readable contract is [api/openapi.yaml](../../api/openapi.yaml). Paths marked `x-status: planned` are not available in the current code.

Validate the contract before changing it:

```bash
npx --yes @redocly/cli@1.34.2 lint api/openapi.yaml
```

The repository's `redocly.yaml` keeps structural and style validation enabled. It disables only the requirement that every endpoint declare a 4xx response, because liveness, readiness, and reserved planned operations do not all have a meaningful 4xx contract.

## Authentication

Browser/API clients use local email/password login. A successful login sets an HTTP-only secure `netp2p_session` cookie and also returns a bearer-capable local session token. The shared break-glass admin token is accepted for operator recovery. Every authenticated request is authorized through the role/module permission matrix.

Implemented public authentication routes:

- `GET /api/v1/bootstrap/status`
- `POST /api/v1/bootstrap/owner`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`
- `GET /api/v1/auth/session`
- `GET /api/v1/auth/status`

The current release implements `POST /api/v1/users/{id}/credentials`. It submits a certified `update_user_credentials` transition, records `credentialsChangedAt`, and rejects sessions issued before that timestamp.

Log in and retain the HTTP-only session cookie:

```bash
curl -fsS --cookie-jar netp2p-cookies.txt \
  -H 'Content-Type: application/json' \
  -d '{"email":"owner@example.com","password":"<password>"}' \
  https://manager-1.netp2p.example:9443/api/v1/auth/login
```

Remove `netp2p-cookies.txt` when the API session is no longer needed.

The endpoint accepts an email and/or password, and each can be changed independently. Email-only changes preserve the existing password. A password must contain at least 12 characters and is stored only as an Argon2id verifier. Password changes reject previously issued local sessions. Self-service password reset remains a controlled operational procedure.

## Implemented API model

The current API is snapshot-oriented. Objects are changed through one authenticated transition endpoint:

```http
POST /api/v1/transitions
Content-Type: application/json

{"transition":{"type":"upsert_group","group":{}}}
```

On success, the committee returns a `SignedSnapshot` with a new BFT height and quorum certificate. The request actor is derived from authentication, not from the body. Transition type names and object shapes are defined by the Go protocol/model code; generic clients should treat `SignedSnapshot.State` as opaque unless they pin the protocol version.

Implemented reads and actions:

| Route | Purpose |
| --- | --- |
| `GET /api/bootstrap` | browser/WebRTC bootstrap metadata |
| `GET /api/v1/snapshot[?height=N]` | latest or historical certified snapshot |
| `GET /api/v1/session` | identity and permission matrix |
| `GET /api/v1/users` | redacted certified user records |
| `POST /api/v1/users/{id}/credentials` | certified email and/or password update |
| `GET /api/v1/presence` | client presence observations |
| `GET /api/v1/activity[?limit=&before=]` | recent certified activity snapshots |
| `GET /api/v1/events[?limit=&before=&type=&actor=]` | certified decision/audit events |
| `GET /api/v1/auth/events[?limit=]` | authentication audit events |
| `GET /api/v1/diagnostics` | operational diagnostics |
| `GET /api/v1/committee/status` | local committee view |
| `GET /api/v1/link-view` | link segments/view |
| `GET /api/v1/assignments` | assignments and admissions |
| `GET /api/v1/routing/status` | aggregate routing and load-balancing status |
| `GET /api/v1/routing/domains` | routing domain authorizations |
| `GET /api/v1/routing/path-families` | certified path families |
| `GET /api/v1/routing/telemetry` | manager edge telemetry |
| `GET /api/v1/routing/demand` | aggregated client demand samples |
| `GET /api/v1/routing/epoch/current` | current signed routing epoch |
| `GET /api/v1/routing/fec` | FEC diagnostics |
| `GET /api/v1/managers/capacity` | manager monthly capacity pressure |
| `GET /api/v1/quota` | quota usage |
| `GET /api/v1/quota/history?period=daily|monthly` | quota history |
| `GET /api/v1/alerts` | active alerts |
| `GET /api/v1/schema` | WebAPI protocol identifier |
| `POST /api/v1/setup-keys` | create a setup key; token is returned once |
| `POST /api/v1/transitions` | authenticated generic BFT transition |

`GET /api/v1/auth/session` and `GET /api/v1/session` both resolve the current
session. Use `/api/v1/auth/session` in authentication-focused clients.

## Routing status

`GET /api/v1/routing/status` returns one aggregate view:

- certified routing domains and path families;
- the complete five-class model: `latency`, `throughput`, `cost`, `reliability`, and `realtime`;
- the current signed `RoutingEpoch`, when the runtime producer is enabled;
- manager monthly capacity pressure;
- edge telemetry;
- aggregated demand samples;
- FEC diagnostics and explicit producer problems.

The focused routes under `/api/v1/routing/*` and
`/api/v1/managers/capacity` return the same objects for clients that need only
one section. Routing reads require the paths permission; manager capacity reads
require the budgets permission. The aggregate routing response omits manager
capacity for callers without budgets permission.

When a runtime producer is unavailable, the API returns an explicit `derived`
or `unavailable` mode and lists the missing inputs. It does not invent a
signature, epoch version, demand sample, or FEC counter.

The manager admin CLI exposes the same certified credential change:

```bash
# admin.yaml contains role: admin, manager, action:
# update-user-credentials, and adminToken.
netp2pd --config-file admin.yaml \
  --email owner@example.com \
  --password-file <new-password-file>
```

For an email replacement, use `--new-email`; lookup by the current address uses `--email`. The CLI requires `--target` or `--email`. Email-only updates preserve the existing password. Protect `admin.yaml` and the password file with restrictive file permissions.

Operationally implemented outside the authenticated API:

- `GET /healthz`
- `GET /readyz`
- `GET /metrics` on the restricted metrics listener

## Planned API resources

The roadmap adds explicit resource APIs while retaining transition compatibility:

- Self-service recovery, scoped administration, and complete credential auditing.
- Dedicated peers, groups, policies, routes, resources, DNS, setup keys, events, tokens, and settings APIs.
- A `Resource` model for IP, CIDR, DNS name, wildcard DNS name, and service/port destinations.
- Routing-peer HA with multiple gateways, metric/failover, health state, and events.
- Service users and scoped PATs with expiry, rotation, and revocation.
- Traffic events/path diagnostics and IPv6 overlay fields.

Until then, use `POST /api/v1/transitions` for supported state changes and verify each accepted change through `GET /api/v1/snapshot?height=<committed height>`.

## Compatibility

The client/manager wire protocol is currently `3.0.0`; clients must match it. REST JSON is versioned by `/api/v1`, but response objects mirror evolving Go protobuf/model structures. Pin the server version in automation, tolerate additive fields, and never rely on undocumented secrets appearing in snapshots.
