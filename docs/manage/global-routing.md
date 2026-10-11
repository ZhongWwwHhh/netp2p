# Global routing and load balancing

Use the Global Routing console page to inspect how certified policy domains,
path families, runtime telemetry, demand, capacity, and signed routing epochs
work together.

## Prerequisites

- A manager you can sign in to with a role that can read paths.
- At least one allow policy or route.
- A client with current certified state.

## Inspect routing state

1. Open **Global Routing** in the console.
2. Filter by flow class, path kind, manager, group, destination scope, or path ID.
3. Confirm the routing domain list contains the expected source group and destination scope.
4. Confirm every eligible domain has at least one certified path family.
5. Check the epoch panel for signature status, version, snapshot height, and expiry.

The five flow classes are `latency`, `throughput`, `cost`, `reliability`, and
`realtime`. `realtime` is pinned unless its SLA or path hard-fails, and ordinary
load rebalancing does not move it.

## Interpret runtime state

- **Manager capacity** shows monthly usage, pressure, and projected exhaustion.
  Capacity is configured as a traffic budget with subject type `manager`.
- **Edge telemetry** shows queue depth, drop rate, active flows, RTT, jitter, loss, and bandwidth.
- **Demand** shows aggregated client reports by routing domain, path, and flow class.
- **FEC** shows packet, recovery, redundancy, and overhead counters by flow class.
- **Problems** state which runtime producers are unavailable. The console does not fabricate a signed epoch or counters.

Runtime observations are not BFT state. They may differ briefly between
managers, and they cannot authorize a path that policy did not certify.

## Validate

From a client:

```bash
netp2p status --json
netp2p netcheck
netp2p ping DESTINATION_OVERLAY_IP
```

Then test the actual TCP or UDP application traffic for the selected flow class.
For realtime traffic, record RTT, jitter, loss, recovered packets, and whether
the flow stayed pinned during ordinary weight changes.

## Troubleshooting

- **No path family**: verify an allow policy, route, and certified assignment exist.
- **No epoch**: confirm the routing status producer is enabled and the epoch has not expired.
- **Capacity pressure**: move demand to another manager path or direct path where policy allows it.
- **Demand missing**: confirm clients are reporting and the reporting window has elapsed.
- **FEC counters stay zero**: confirm the class is realtime or reliability with FEC enabled.
