# Security model

## Control plane

Three managers form a HotStuff-style BFT committee. A client mutation becomes a signed proposal, receives Ed25519 votes, forms a quorum certificate, and commits a certified snapshot. For production `n=3/f=0/quorum=3`, all three managers must sign. Clients verify snapshots against the embedded committee configuration and reject incomplete or untrusted certificates.

DKG establishes the committee's threshold/group key material. Per-manager private shares, identity keys, seeds, and the SQLite ledger are local secrets. The public certified snapshot contains committee public configuration, not private shares.

## Authentication and passwords

- Browser/API users authenticate by email/password.
- Passwords are stored only as Argon2id verifiers, never plaintext or reversible hashes.
- Login attempts are rate limited; five failures lock the account for 15 minutes.
- Sessions are signed local tokens issued through secure, HTTP-only, SameSite cookies. A static admin token is supported as break-glass and is not a replacement for user accounts.
- The working tree adds a certified credentials endpoint and CLI. It stores Argon2id verifiers, rejects pre-change sessions through `credentialsChangedAt`, protects owner records, and writes auth audit events. Email and password can be updated independently. Self-service password recovery is still not implemented; recoveries remain controlled, audited operational procedures.

Planned v0.3 controls: self-service recovery, service-user PATs with scopes/expiry/rotation, and complete credential audit exports.

## Authorization

Every control-plane mutation passes one authenticated boundary. The authenticated identity is converted to an actor server-side; a request cannot forge the audit actor. Roles and modules are checked before a transition is submitted. Committee messages are accepted from configured committee peers; ordinary unauthenticated HTTP callers cannot advance state.

## Setup keys and secrets

- Setup-key enrollment tokens are shown once by the creating API/CLI.
- Certified snapshots store hash/verifier and metadata rather than reusable plaintext enrollment secrets.
- Manager admin/session tokens, DKG shares, seed material, password files, PATs, and client identity keys must never be committed, logged, or embedded unintentionally in support bundles.
- Client-visible snapshots are redacted for password verifiers and secret-bearing records.

Use short-lived setup keys, delete/disable unused records, rotate break-glass material after administrative use, and encrypt backups.

## Data plane

libp2p provides peer identity, secure channels, QUIC/WebRTC transport, NAT traversal, and relay. Certified assignments and policies drive forwarding; frames are accepted only within authorized path/admission state. Do not infer connectivity from peer status alone; test both directions with ICMP/TCP.

The client should fail closed when policy requires no direct path or when manager forwarding is unavailable under certified settings. Route/DNS changes are reconciled from state and cleaned up on graceful shutdown; investigate unexpected host route or DNS state after a crash.

## Transport and web

HTTPS is terminated by Caddy on 9443. Keep certificates renewing and do not proxy manager UDP paths through Cloudflare. Browser cookies require HTTPS and are HTTP-only. Keep the metrics listener off the public internet.

## Threat model

Assume the public internet can reach manager UDP/HTTPS ports. Security depends on:

- BFT quorum and snapshot signature verification
- committee peer authentication
- authenticated API boundaries and RBAC
- Argon2id password storage and session integrity
- secret redaction and encrypted backups
- host firewall and least-privilege containers
- current clients and timely certificate/token rotation

Not protected by NetP2P alone: a compromised owner browser/session, compromise of all manager hosts/shares/seeds, a malicious client with valid enrollment and policy access, or host-level kernel/firewall compromise. Limit owner access, rotate credentials, preserve audit logs, and restore from a pre-compromise committee-wide backup when required.
