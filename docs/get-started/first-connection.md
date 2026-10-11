# Verify your first connection

Confirm that two enrolled peers can communicate in both allowed directions.

## Prerequisites

- Two peers with `ready` status.
- The overlay IP printed by `netp2p ip` on each peer.
- A policy allowing the peers' groups.

## Check status

Run on both peers:

```bash
netp2p status
netp2p status --json
netp2p ip
netp2p doctor
```

Record each overlay IP and confirm the daemon is `ready`.

## Probe both directions

On peer A:

```bash
netp2p ping B_OVERLAY_IP
```

On peer B:

```bash
netp2p ping A_OVERLAY_IP
```

If both succeed, run a workload-specific TCP or UDP test for the applications you
need. `netp2p ping` validates overlay reachability but not every application
port.

## Troubleshooting

- **One direction fails**: check that policy is bidirectional or add matching
  rules for each required direction.
- **Both directions fail**: confirm both peers are present, are in allowed
  groups, and refresh certified state with `netp2p up`.
- **Status says direct but traffic fails**: path selection is not proof of a
  successful probe. Continue with `netp2p doctor` and application-level tests.
- **DNS name does not resolve**: check overlay DNS configuration and the peer
  DNS label.
