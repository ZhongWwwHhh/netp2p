# Upgrading NetP2P

NetP2P v0 has no cross-version wire compatibility. Every manager and every
client in a network must run the same protocol version, which is reported by
`netp2pd --role doctor` and by `GET /api/v1/schema`.

## What the protocol version covers

`internal/version.ProtocolVersion` is embedded in every libp2p protocol id
(`/netp2p/.../<version>`). A peer that speaks a different version cannot open a
stream to the new protocol, and a control message with an unknown field fails
protobuf validation. Both are deliberate: a mismatched node is rejected with an
explicit error instead of silently diverging from certified state.

When the version changes, the certified state hash algorithm may also change
(it is `sha256` over deterministic protobuf). Two nodes on different versions
would therefore compute different `StateHash` values for the same logical
state, which is why the cut-over must be atomic.

## Upgrade order

1. **Drain writes.** Stop submitting console/CLI changes. The committee keeps
   serving reads and keeps certification alive.
2. **Stop all managers.** A rolling restart is *not* supported: a mixed
   committee cannot reach quorum because the new members' proposals fail the
   old members' validation and vice versa. Stop `netp2pd` on every manager.
3. **Replace the binaries.** Install the new `netp2pd` on all managers, then on
   all clients.
4. **Start all managers.** They reconnect, the mesh re-forms with the same
   `CommitteeEpoch`, and the committee resumes at height 0 (v0 keeps no
   persistent ledger) — or, if snapshots were persisted by your deployment,
   each manager catches up to the certified height via the one-height-at-a-time
   sync exchange.
5. **Start clients.** Clients re-login; SSO peers run the device flow again.

Because v0 has no on-disk consensus log, a restart re-certifies from the seed.
Seed-only state (committee members, groups, policies, budgets, setup keys) is
therefore authoritative across the upgrade.

## Committee key rotation

`rotate_committee_keys` bumps `CommitteeEpoch` and derives a fresh BLS12-381
keyset from the seed. Order matters:

1. All managers must be online; rotation needs a quorum of the *current*
   committee to commit.
2. Submit `rotate-committee-keys` through the admin CLI or console.
3. The commit is signed with the old epoch and adopted atomically; every
   subsequent proposal and vote uses the new epoch.
4. Clients validate snapshots against the `CommitteeConfig` carried in the
   snapshot, so a client that receives a stale-epoch snapshot rejects it and
   re-syncs.

Replacing members uses `update_committee`, which can swap at most one member
(`f = 1`) per transition and must leave at least one forwarding member. A new
member must carry a valid peer id, address and BLS public key before the
transition is accepted.

## Disaster recovery when a manager key is lost

v0 derives share keys deterministically from the seed plus `CommitteeEpoch`, so
recovery does not need a key ceremony:

1. Re-generate the seed with `netp2pd --role seedgen --config <seed.json>` on a
   trusted machine.
2. Bring a quorum of surviving managers online and commit `rotate_committee_keys`
   to force a new epoch.
3. Reinstall the lost manager with the regenerated seed and let it catch up.

If the seed itself is lost, the network cannot be recovered in place: there is
no way to reconstruct the group public key. Treat the seed as the root of trust
and back it up accordingly.

## Rollback

Roll back by reinstalling the previous binaries on *every* node and restarting
the committee together. A single-node rollback cannot reach quorum and must not
be attempted during production traffic.

## Packaging and privileges

- `make package VERSION=x.y.z` builds DEB and RPM packages via nfpm, plus a
  systemd unit that runs `netp2pd --role doctor` as an `ExecStartPre` check.
- The Debian/RPM unit grants only `CAP_NET_ADMIN` (needed for TUN and DNS
  takeover) and drops the rest.
- The container's `runtime` stage runs as the unprivileged `netp2p` user. For
  TUN or DNS takeover, add `--cap-add NET_ADMIN` and pass
  `--device /dev/net/tun`; the host path `/var/lib/netp2p` must be writable by
  uid/gid 999.

## Exit nodes and subnet routes

An exit/subnet gateway needs the kernel to forward and (optionally) masquerade
traffic, so it has stricter host requirements than a plain client:

- Linux only, with a working TUN device (`/dev/net/tun`) and `CAP_NET_ADMIN`.
  Without them `netp2pd` logs an explicit warning and disables exit capability
  on that node; it still works as an ordinary peer.
- `iptables` must be installed. The gateway installs managed
  `POSTROUTING ... MASQUERADE` (only for routes with `masquerade: true`) and
  `FORWARD ... ACCEPT` rules and flips `net.ipv4.ip_forward` on, restoring the
  previous value when it stops. The `netp2p-test` image already includes
  `iptables`.
- Marking a peer as an exit node is a certified change (`update_peer`), not a
  local flag: use the Peers page (needs `peers:update`) or
  `netp2pd --role admin --action update-peer --file peer.json` with
  `{"peerId":"<id>","isExitNode":true}`. The route itself is a normal
  `upsert-route` whose routing group must contain that peer.
- On the container runtime, start the gateway with `--cap-add NET_ADMIN`,
  `--device /dev/net/tun`, and (for a real default route) a corresponding
  network attachment. Do not run the gateway as the unprivileged `runtime`
  stage without those grants.
