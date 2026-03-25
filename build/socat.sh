#!/bin/sh
set -e

# echo "sleep 5..."
# sleep 10
echo "start script"
# Create minimal /etc/hosts so getaddrinfo can resolve 0.0.0.0 / 127.0.0.1
echo "127.0.0.1 localhost" >> /etc/hosts
echo "127.0.0.2 oprf-tee-testnet-0-cluster-prod.cluster-c1i26k0aa2nn.eu-central-1.rds.amazonaws.com" >> /etc/hosts
echo "127.0.0.2 oprf-tee-testnet-1-cluster-prod.cluster-c1i26k0aa2nn.eu-central-1.rds.amazonaws.com" >> /etc/hosts
echo "127.0.0.2 oprf-tee-testnet-2-cluster-prod.cluster-c1i26k0aa2nn.eu-central-1.rds.amazonaws.com" >> /etc/hosts
# echo "127.0.0.3 alchemy.com" >> /etc/hosts
echo "127.0.0.3 opt-mainnet.g.alchemy.com" >> /etc/hosts
echo "127.0.0.4 crs.aztec.network" >> /etc/hosts
# Create minimal nsswitch.conf so glibc knows to check /etc/hosts
echo "hosts: files" > /etc/nsswitch.conf
cat /etc/hosts
# Bring up the loopback interface
ip link set lo up
# Verify it's up
ip addr show lo

echo "Ensure loopback addresses exist"
if ! ip addr show dev lo | grep -q "127.0.0.2"; then
  ip addr add 127.0.0.2/32 dev lo:0
  ip link set dev lo:0 up
fi
if ! ip addr show dev lo | grep -q "127.0.0.3"; then
  ip addr add 127.0.0.3/32 dev lo:0
  ip link set dev lo:0 up
fi
if ! ip addr show dev lo | grep -q "127.0.0.4"; then
  ip addr add 127.0.0.4/32 dev lo:0
  ip link set dev lo:0 up
fi
if ! ip addr show dev lo | grep -q "127.0.0.5"; then
  ip addr add 127.0.0.5/32 dev lo:0
  ip link set dev lo:0 up
fi
if ! ip addr show dev lo | grep -q "127.0.0.200"; then
  ip addr add 127.0.0.200/32 dev lo:0
  ip link set dev lo:0 up
fi
# sleep 5


# echo "Start vsock proxies"
# # Connections from Enclave
# vscproxy -parentCID=3 -vsockPort=5432 -localAddr=127.0.0.2:5432 &
# sleep 5


# echo "Forward 5432 port"
# # forward db request from the enclave to outside
socat TCP-LISTEN:5432,bind=127.0.0.2,fork,reuseaddr,keepalive VSOCK-CONNECT:3:5432,keepalive &

# # forward rpc requests to the outside
socat TCP-LISTEN:443,bind=127.0.0.3,fork,reuseaddr,keepalive VSOCK-CONNECT:3:4444,keepalive &

# # forward requests to get crs (bb) to the outisde
socat TCP-LISTEN:80,bind=127.0.0.4,fork,reuseaddr,keepalive VSOCK-CONNECT:3:4445,keepalive &
# socat iTCP-LISTEN:443,bind=127.0.0.5,fork,reuseaddr,keepalive VSOCK-CONNECT:3:4446,keepalive &

#
# echo "Forward 443 port"
# # forward rpc requests from the enclave to outside
# socat TCP-LISTEN:443,bind=0.0.0.0,fork,reuseaddr,keepalive VSOCK-CONNECT:21:443,keepalive &
#
PORT=5005
OUT_FILE=/app/.env

echo "Listening and writing to $OUT_FILE..."

socat VSOCK-LISTEN:${PORT},fork,reuseaddr OPEN:${OUT_FILE},creat,append &

echo "Config written to $OUT_FILE:"
sleep 5
echo "Contents of $OUT_FILE:"
cat $OUT_FILE



echo "Accepting outside connection on port 4563"
# listen to http connections from outside
socat VSOCK-LISTEN:4563,fork,keepalive TCP:127.0.0.1:4563,keepalive &

set -a && . /app/.env && set +a
echo "before starting oprf"
RUST_LOG=debug /app/taceo-oprf-testnet-node || true
echo "exiting in 100 seconds..."
sleep 100
