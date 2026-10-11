# DNS

Configure peer-name resolution, custom overlay zones, and selective upstream
nameservers.

## Prerequisites

- Owner or network administrator access.
- At least one enrolled peer that should receive DNS configuration.
- Upstream resolver addresses for split DNS.

## Peer names

Each enrolled peer receives a DNS label. With a network-wide DNS domain, peers
can address each other by that name instead of an overlay IP. The exact domain
and search behavior come from certified network settings.

## Add a zone

Create an authoritative overlay zone with records such as:

```json
{
  "id": "internal-example",
  "domain": "internal.example",
  "records": [
    {"name": "app.internal.example", "type": "A", "value": "203.0.113.11", "ttl": 60}
  ],
  "groups": ["workstations"],
  "enabled": true
}
```

Submit the zone through the console DNS area, then refresh clients.

## Configure split DNS

Add a nameserver object:

```json
{
  "id": "office-resolver",
  "name": "Office resolver",
  "groups": ["workstations"],
  "matchDomains": ["office.example"],
  "servers": ["203.0.113.12"],
  "primary": true,
  "enabled": true
}
```

Only listed groups use this resolver. Non-empty match domains scope it to those
suffixes; an empty list makes it general-purpose for those groups.

## Validate

```bash
netp2p up
netp2p status --json
nslookup app.internal.example
```

On Windows, prefer `Resolve-DnsName app.internal.example` over a cached
`nslookup` result.

## Troubleshooting

- **No answer**: refresh the client and verify the record, zone, and group.
- **Unexpected answer**: clear the OS DNS cache or use a fresh lookup.
- **Split DNS misses private names**: confirm the suffix exactly matches the
  query and the client is in the nameserver group.
- **Local DNS breaks**: run `netp2p down`, then `doctor`, before changing host
  resolver files manually.
