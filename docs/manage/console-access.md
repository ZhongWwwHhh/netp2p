# Console access

Create the first owner, sign in, and keep console sessions safe.

## Prerequisites

- Network reachability to the manager console.
- Owner email and password, or no existing owner for initial bootstrap.

## Open the console

Use the console address published by your deployment, for example:

```text
https://console.netp2p.example:9443/
```

A self-hosted deployment may publish a single console hostname or one hostname
per manager. For direct-manager diagnosis, use the exact manager hostname given
by your operator, such as `manager-1.netp2p.example`,
`manager-2.netp2p.example`, or `manager-3.netp2p.example`.

## Bootstrap the first owner

The first-owner screen appears only when no owner exists.

1. Open the console.
2. Choose **Create owner**.
3. Enter a valid email, display name, and password of at least 12 characters.
4. Store the credential in your organization's approved secret manager.

The console creates the owner user and owners group through certified state,
then starts an HTTP-only session. Bootstrap is possible only once.

## Sign in and out

Sign in with email and password. Logout clears the browser session cookie.
Five failed attempts lock the account for 15 minutes. A password change revokes
that user's existing sessions.

## Troubleshooting

- **First-owner form is absent**: an owner already exists; sign in or use the
  controlled owner credential reset process.
- **Account locked**: wait for lockout to expire or use an approved reset path.
- **Certificate warning**: use the console hostname published by your operator
  and verify the deployment's TLS certificate setup.
- **Session disappears repeatedly**: avoid private-mode browser restrictions and
  synchronize clocks.
