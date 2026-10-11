# Create a network

Create the initial owner account, owners group, allow policy, and initial setup
key.

## Audience

Use this when you are starting a new network and will run its first manager.

## Prerequisites

- A host for the first manager.
- Installed `netp2pd` and `netp2p` binaries.
- An owner email address.
- A password of at least 12 characters.

## Create bootstrap files

Run this on the manager host. It creates the seed, runtime configuration, owner
credentials, and an initial reusable setup key. Generated secrets are written to
protected files and are printed only when explicitly requested.

```bash
netp2p init network \
  --network example-network \
  --owner-email owner@example.com \
  --owner-name "Network Owner" \
  --data-dir /var/lib/netp2p \
  --seed /etc/netp2p/seed.json \
  --config /etc/netp2p/runtime.yaml \
  --setup-key-file /root/example-setup-key
```

Adjust paths for Windows. Delete the setup-key file after enrollment.

## Start the manager

For a local test:

```bash
netp2pd --role manager --config /etc/netp2p/runtime.yaml
```

When the console is available, sign in as the owner and confirm the network ID,
protocol version, certified height, and committee status.

## Validation

- The daemon starts without configuration errors.
- The console reports the network as ready.
- The initial setup key is present and not revoked.
- A client can enroll with the manager endpoint and setup key.

## Troubleshooting

- **Missing owner email**: pass `--owner-email` or use interactive mode.
- **Unwritable paths**: choose directories owned by the service account.
- **Setup key missing**: create a replacement key after bootstrap instead of
  regenerating network state once clients depend on it.
