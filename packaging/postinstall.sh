#!/bin/sh
# Refresh systemd and enable nothing automatically: an operator must provide a
# seed and runtime config before the node can start.
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi
echo "netp2p installed. Edit /etc/netp2p/runtime.yaml and provide a seed,"
echo "then run 'netp2pd --role doctor --config-file /etc/netp2p/runtime.yaml'."
