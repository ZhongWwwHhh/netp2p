# Login and enrollment issues

Fix problems where a client cannot join or authenticate.

## Symptoms

- `needs-login` never clears
- Setup key rejected
- Login loop
- Wrong overlay IP after login

## Diagnosis

Run:

```bash
netp2p status --json
netp2p doctor
```

Then check the manager endpoint is reachable:

```bash
curl -fsS https://manager-1.netp2p.example:9443/readyz
```

## Fixes

| Symptom | Cause | Action |
| --- | --- | --- |
| `needs-login` | No enrollment material | Run `netp2p login` with a valid setup key and manager endpoint |
| Setup key rejected | Expired, used up, wrong group, wrong manager | Ask admin to reissue with correct expiry and group |
| Login loops | Daemon cannot validate or sync local state | Run `netp2p down`, capture `status --json` and `doctor`, then restart the daemon |
| Wrong overlay IP | Stale cache vs certified snapshot | Inspect `status --json`; restart daemon to force sync |
| 401 on console | Expired cookie | Sign in again |
| 429 / locked | Five failed attempts | Wait 15 minutes, then retry |

## Not available

Self-service password recovery is not implemented. Owner/CLI-controlled
recovery is a managed, audited operational procedure.

`logout` clears setup-key or SSO credentials from the runtime config; it does
not repair or delete the local identity. If the profile is corrupt, restore it
from a debug bundle or intentionally remove the client data directory and
re-enroll.
