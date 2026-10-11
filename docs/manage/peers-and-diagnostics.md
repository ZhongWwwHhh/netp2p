# Peers, diagnostics, and audit

Use the console to verify peer presence, path health, traffic controls, and the
certified change log.

## Check peers

The peers area shows peer ID, overlay IP, groups, hostname, OS, client version,
user ID, DNS label, last login, exit-node flag, posture labels, and presence.

Confirm expected peers are present, groups are correct, client versions are
compatible with protocol `3.0.0`, and exit-node flags are intentional.

## Diagnose health

The overview and diagnostics area exposes manager health, committee
connectivity, certified height, forwarding counters, active alerts, quota state,
assignments, and link views.

Before changing policy or routes, confirm:

1. The manager is reachable.
2. Committee connectivity/quorum is available.
3. Certified state is loaded.
4. The affected peer is present.

## Diagnose a client

Run on the client:

```bash
netp2p status --json
netp2p doctor
netp2p netcheck
netp2p ping DESTINATION_OVERLAY_IP
netp2p debug bundle
```

Remove tokens and secrets before sending a debug bundle to anyone else. Treat a
path marked `direct` as selection information; validate the flow with a probe.

## Review activity

The activity and audit views show certified transition events with height,
transition type, actor, leader, signer bitmap, committee epoch, state hash, and
transition hash. Authentication events are available separately.

For an access incident, compare certified policy and group state at the relevant
height with client presence and traffic-event data.

## Troubleshooting

- **Peer missing**: enroll or reconnect it and check daemon state.
- **Height does not increase**: stop making changes and restore committee quorum.
- **Quota unexpectedly enforces**: inspect budgets and quota settings.
- **No audit event**: the change was not accepted; check role permissions and the
  submitted transition.
