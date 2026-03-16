#!/bin/sh
set -e

echo "sleep 20..."
sleep 20
echo "start script"
# Create minimal /etc/hosts so getaddrinfo can resolve 0.0.0.0 / 127.0.0.1
echo "127.0.0.1 localhost" > /etc/hosts

# Create minimal nsswitch.conf so glibc knows to check /etc/hosts
echo "hosts: files" > /etc/nsswitch.conf
cat /etc/hosts
# Bring up the loopback interface
ip link set lo up
# Verify it's up
ip addr show lo

echo "Waiting for 8000 port"
# listen to http connections from outside
socat VSOCK-LISTEN:8000,fork,keepalive TCP:127.0.0.1:8000,keepalive &

echo "Forward 5432 port"
# forward db request from the enclave to outside
socat TCP-LISTEN:5432,bind=0.0.0.0,fork,reuseaddr,keepalive VSOCK-CONNECT:21:5432,keepalive &

echo "Forward 443 port"
# forward rpc requests from the enclave to outside
socat TCP-LISTEN:443,bind=0.0.0.0,fork,reuseaddr,keepalive VSOCK-CONNECT:21:443,keepalive &

set -a && . /app/.env && set +a
echo "before sleep"
sleep 100
ls
ls -l /app/
echo "before starting oprf"
/app/taceo-oprf-testnet-node
