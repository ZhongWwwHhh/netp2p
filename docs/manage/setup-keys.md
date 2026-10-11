# Setup keys

Use setup keys to enroll a machine without giving it an administrator password.

## Key types

| Type | Use |
| --- | --- |
| Reusable | Multiple machines, with an optional usage limit |
| One-off | A single enrollment |

Every key has groups, optional expiry, optional usage limit, use count, and
revocation state. The committee stores only a verifier, not the plaintext token.

## Create a key

1. Open **Setup keys**.
2. Choose **Create key**.
3. Enter a descriptive name.
4. Select reusable or one-off.
5. Select the groups assigned to peers enrolled with it.
6. Set a short expiry or usage limit for automated workflows.
7. Copy the plaintext token immediately.

The plaintext is shown once. Store it in your organization's approved secret
manager if automation needs it later; if it is lost, create a replacement key.

## Enroll with a key

- Linux: [Join a Linux peer](../get-started/join-linux.md).
- Windows: [Join a Windows peer](../get-started/join-windows.md).

## Rotate or revoke

1. Create the replacement key and distribute it to enrollment automation.
2. Revoke the old key.
3. Confirm new enrollment attempts fail.
4. Update existing peers separately if you need to change their groups.

Do not rely on deletion alone for incident response; revoke first.

## Troubleshooting

- **Token rejected**: check expiry, revocation, type, and usage limit.
- **Peer lacks access**: check the key's groups and effective policies.
- **Console does not show the token again**: expected; create a replacement.
- **Automation exposes the key**: rotate it and remove it from logs, images, and
  command history.
