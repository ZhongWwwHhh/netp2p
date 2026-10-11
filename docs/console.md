# Web console

## URLs

- Primary: <https://console.netp2p.example:9443/>
- Direct: <https://manager-1.netp2p.example:9443/>, <https://manager-2.netp2p.example:9443/>, <https://manager-3.netp2p.example:9443/>

The primary hostname resolves to all three managers and is not health-aware. If it selects an unhealthy node, use a direct URL. Browser certificates are issued by the deployment's public CA/DNS-01 setup.

## First owner setup

1. Open the console while no owner exists. `GET /api/v1/bootstrap/status` returns `"needsOwner": true`.
2. Use **Create owner** in the console, or `POST /api/v1/bootstrap/owner`, to set a valid email, name, and password of at least 12 characters.
3. The request creates the `owners` group and owner user through BFT, then starts a secure, HTTP-only session cookie.

Only one owner bootstrap is possible. Once an owner exists, `needsOwner` remains false and the endpoint returns 409.

## Sign in and out

Use email and password on the console login page. Five consecutive failures lock that account for 15 minutes. Logout clears the browser cookie. Local session tokens are manager HTTP session tokens, not BFT committee credentials.

Do not put passwords or owner credentials in URLs, shell history, screenshots, tickets, or client profiles.

## Console areas

- **Overview/diagnostics**: network ID, protocol version, BFT height, committee connectivity, peers, forwarding counters, and active alerts.
- **Peers**: certified peer records, overlay IPs, groups, host/OS metadata, and exit-node flag.
- **Users**: email, name, role, groups, and blocked state. The UI shows public user records; password verifiers are stripped. A working-tree credentials API/CLI can update email or password independently and revoke older sessions after a password change.
- **Groups**: API-created or JWT/SSO-managed groups of users and peers.
- **Policies**: source/destination groups, protocol/port services, allow/deny effect, direction, posture requirements, priority, and flow class.
- **Routes**: destination CIDR, routing group, distribution groups, metric/path constraints, budget links, and masquerade. Routing resources with HA gateways are planned for v0.3.0.
- **DNS**: certified zones, records, nameservers, and DNS settings.
- **Setup keys**: create one-off/reusable keys with expiry and target groups. The token appears once in the create response; later snapshots contain only non-reversible metadata/hash data.
- **Events/audit**: certified decision-log entries plus authentication events.
- **Quota**: budgets, live usage, and daily/monthly history.

## Change model

The current authenticated API uses `POST /api/v1/transitions` with a typed `StateTransition`, rather than a separate REST CRUD endpoint per object. The actor is derived from the authenticated session or break-glass token; request-supplied actors are ignored. Every accepted change becomes a certified BFT height and can be inspected by height.

Roles map to module permissions. `owner` has full access; `admin`, `network_admin`, `auditor`, `usage_viewer`, and `user` have progressively narrower access. The session response exposes the effective permission matrix.

## Safe workflow

1. Verify committee is 3/3 connected before writes.
2. Make one policy or route change.
3. Refresh the snapshot and confirm the new height.
4. Probe traffic from an affected client.
5. Use the certified event at the new height as the audit record.
