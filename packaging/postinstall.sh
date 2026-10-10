#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi
echo "NetP2P installed."
echo "Initialize a network with: netp2p init network"
echo "Manage it with: netp2p up, netp2p down, netp2p status, netp2p doctor"
