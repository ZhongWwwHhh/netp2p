# DNS and route issues

Fix problems with name resolution, subnet routes, or broken external connectivity.

## Symptoms

- External DNS broken after NetP2P starts
- Overlay names do not resolve
- Route loss after a crash
- Exit node traffic blocked

## Diagnosis

```bash
netp2p doctor
netp2p status --json
```

Test overlay and external names separately:

```bash
nslookup some-overlay-name.<overlay-domain>
nslookup example.com
```

On Linux, inspect the current resolver:

```bash
cat /etc/resolv.conf
resolvectl status
ip route show table main
```

On Windows, inspect DNS and routes from elevated PowerShell:

```powershell
Get-DnsClientNrptRule
Get-NetRoute -AddressFamily IPv4
Resolve-DnsName some-overlay-name.<overlay-domain>
Resolve-DnsName example.com
```

## Fixes

| Finding | Action |
| --- | --- |
| External DNS broken | Verify only overlay domains use the NetP2P resolver; upstreams must remain reachable |
| Overlay names fail | Check certified DNS zones/settings and the local resolver listener |
| Route loss after crash | Run `netp2p doctor`, then restart the service for managed cleanup |
| Exit node blocked | Gateway needs TUN, `iptables`, `CAP_NET_ADMIN`, and a certified route with masquerade if required |

Do not manually destroy routes or DNS state while the service is running
unless a diagnostic directs it; use `netp2p down` or a service restart first.
