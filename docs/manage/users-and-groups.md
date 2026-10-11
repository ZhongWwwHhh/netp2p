# Users and groups

Create groups and use them as stable policy selectors for users and peers.

## Prerequisites

- Owner or administrator console access.
- A named audience, such as `servers`, `workstations`, or `contractors`.

## Create a group

From the groups area, create a group with a stable ID and display name. API
automation uses an authenticated typed group transition at
`POST /api/v1/transitions`; the exact request envelope is described by the
deployment's API schema.

A representative API group object is:

```json
{
  "id": "servers",
  "name": "Servers",
  "userIds": [],
  "issued": "api"
}
```

Submit the change, then refresh and confirm that certified height increased.

## Add users

1. Open the users area.
2. Select the user record.
3. Add or remove API-issued group membership.
4. Save and confirm the new certified height.

Users expose public records only. Password verifiers are not included in
client-visible state.

## Add peers

Peers receive groups from the setup key used to enroll and can be updated later.
Open the peer record, change its groups, save, and refresh the client with
`netp2p up`.

## Validation

```bash
netp2p up
netp2p status --json
```

Confirm the peer shows the expected groups and only reaches policy-allowed
destinations.

## Troubleshooting

- **Group change does not take effect**: refresh the client snapshot.
- **Unexpected access**: inspect source and destination selectors on every
  applicable policy.
- **Cannot remove a group**: remove or update policies and setup keys that
  reference it first.
- **Cannot change credentials**: owner credentials require owner authorization;
  password changes revoke the user's sessions.
