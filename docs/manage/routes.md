# Routes and routing peers

Use routes to expose subnets, exit-node access, or other destinations through a
routing peer.

## Prerequisites

- A peer able to act as a routing peer, usually Linux with forwarding enabled.
- A destination CIDR or exit-node scope.
- Groups for routing-peer distribution and destination access.
- Globally enabled exit/subnet routing when using those features.

## Understand the split

- **Route**: how traffic reaches a destination and through which peers.
- **Policy**: which source groups may reach that destination.

A route alone does not authorize users. Pair it with a policy.

## Publish a subnet

Create a route with a shape like:

```json
{
  "id": "office-lan",
  "name": "Office LAN",
  "destination": "203.0.113.0/24",
  "routingGroup": "route-gateways",
  "distributionGroups": ["workstations"],
  "metric": 100,
  "masquerade": true
}
```

Submit the route in the console routes area. Then add a policy allowing the
source group to reach the routed destination or the groups that represent it.

## Enable an exit node

1. Mark an approved peer as an exit node in its peer record.
2. Enable exit-node routing in network settings when required.
3. Add a route or distribution scope for clients that should use it.
4. Add a policy authorizing the required destinations.
5. Refresh clients.

## Validate

On a client:

```bash
netp2p up
netp2p status --json
ping 203.0.113.13
```

Replace `203.0.113.13` with an address that actually exists behind the routing
peer. Test the real TCP or UDP service as the final check.

## Troubleshooting

- **No route is installed**: confirm the client is in the route's distribution
  groups and refresh certified state.
- **Routing peer is unreachable**: check its `ready` state, forwarding settings,
  and host firewall.
- **Remote host does not reply**: add return routing or masquerade and check the
  destination host firewall.
- **Access does not match intent**: separate route reachability from policy
  authorization and inspect both.
