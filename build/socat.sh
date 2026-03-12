#!/bin/sh
set -e

# Create minimal /etc/hosts so getaddrinfo can resolve 0.0.0.0 / 127.0.0.1
echo "127.0.0.1 localhost" > /etc/hosts

# Create minimal nsswitch.conf so glibc knows to check /etc/hosts
echo "hosts: files" > /etc/nsswitch.conf
cat /etc/hosts
# Bring up the loopback interface
ip link set lo up
# Verify it's up
ip addr show lo

socat VSOCK-LISTEN:8000,fork,keepalive TCP:127.0.0.1:8000,keepalive &

set -a && source .env && set +a
# sleep 100
ls
ls -l /app/
/app/taceo-oprf-testnet-node
