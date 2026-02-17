#!/usr/bin/env bash

set -eu

NOCOLOR='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'

PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

wait_for_health() {
    local port=$1
    local name=$2
    local timeout=${3:-60}
    local start_time=$(date +%s)
    echo "waiting for $name on port $port to be healthy..."

    while true; do
        http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$port/health" || echo "000")
        if [[ "$http_code" == "200" ]]; then
            echo "$name is healthy!"
            break
        fi
        now=$(date +%s)
        if (( now - start_time >= timeout )); then
            echo -e "${RED}error: $name did not become healthy after $timeout seconds${NOCOLOR}" >&2
            exit 1
        fi
        sleep 1
    done
}

wait_for_oprf_pub() {
    local port=$1
    local timeout=${3:-60}
    local start_time=$(date +%s)
    local oprf_key_id=$2
    echo "waiting for orpf key id $oprf_key_id on port $port to be ready..."

    while true; do
        http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$port/oprf_pub/$oprf_key_id" || echo "000")
        if [[ "$http_code" == "200" ]]; then
            echo "Found oprf key id $oprf_key_id"
            break
        fi
        now=$(date +%s)
        if (( now - start_time >= timeout )); then
            echo -e "${RED}error: oprf key id $oprf_key_id was not found after $timeout seconds${NOCOLOR}" >&2
            exit 1
        fi
        sleep 1
    done
}

deploy_contracts() {
    # deploy OprfKeyRegistry for 3 nodes and register anvil wallets 7,8,9 as participants
    (cd contracts && TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 THRESHOLD=2 NUM_PEERS=3 forge script script/deploy/OprfKeyRegistryWithDeps.s.sol --broadcast --fork-url http://127.0.0.1:8545 --private-key $PK)
    # this should stay constant unless the contract changes, is also hardcoded in contracts/script/config/local.json
    oprf_key_registry=$(jq -r '.transactions[] | select(.contractName == "ERC1967Proxy") | .contractAddress' ./contracts/broadcast/OprfKeyRegistryWithDeps.s.sol/31337/run-latest.json)
    (cd contracts && TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 OPRF_KEY_REGISTRY_PROXY=$oprf_key_registry PARTICIPANT_ADDRESSES=0x14dC79964da2C08b23698B3D3cc7Ca32193d9955,0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f,0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 forge script script/RegisterParticipants.s.sol --broadcast --fork-url http://127.0.0.1:8545 --private-key $PK)
    echo "OprfKeyRegistry: $oprf_key_registry"
}

start_node() {
    local i="$1"
    local port=$((10000 + i))
    local db_port=$((5440 + i))
    local db_conn="postgres://postgres:postgres@localhost:$db_port/postgres"
    RUST_LOG="taceo_oprf_service=trace,taceo_oprf_testnet_node=trace,taceo_oprf_testnet_authentication=trace,warn" \
    ./target/release/taceo-oprf-testnet-node \
        --bind-addr 127.0.0.1:$port \
        --environment dev \
        --version-req ">=0.0.0" \
        --oprf-key-registry-contract $oprf_key_registry \
        --db-connection-string $db_conn \
        --db-schema oprf \
        --unkey-verify-key "test" \
        --ws-max-message-size 51200 \
        --vk-path ./oprf-testnet-authentication/blinded_query_proof.vk \
        > logs/node$i.log 2>&1 &
    pid=$!
    echo "started taceo-oprf-testnet-node $i with PID $pid"
}

teardown() {
    docker compose -f ./oprf-testnet-node/deploy/docker-compose.yml down || true
    killall -9 taceo-oprf-testnet-node 2>/dev/null || true
    killall -9 anvil 2>/dev/null || true
}

setup() {
    rm -rf logs
    mkdir -p logs
    teardown
    trap teardown EXIT SIGINT SIGTERM

    cargo build --workspace --release

    anvil  &> logs/anvil.log &

    docker compose -f ./oprf-testnet-node/deploy/docker-compose.yml up -d localstack oprf-node-db0 oprf-node-db1 oprf-node-db2

    echo -e "${GREEN}deploying contracts..${NOCOLOR}"
    deploy_contracts

    echo -e "${GREEN}starting OPRF key-gen nodes..${NOCOLOR}"
    docker compose -f ./oprf-testnet-node/deploy/docker-compose.yml exec localstack sh -c "AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test aws --endpoint-url=http://localhost:4566 --region us-east-1 secretsmanager create-secret --name oprf/eth/n0 --secret-string 0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356"
    docker compose -f ./oprf-testnet-node/deploy/docker-compose.yml exec localstack sh -c "AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test aws --endpoint-url=http://localhost:4566 --region us-east-1 secretsmanager create-secret --name oprf/eth/n1 --secret-string 0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97"
    docker compose -f ./oprf-testnet-node/deploy/docker-compose.yml exec localstack sh -c "AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test aws --endpoint-url=http://localhost:4566 --region us-east-1 secretsmanager create-secret --name oprf/eth/n2 --secret-string 0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"
    OPRF_KEY_GEN_OPRF_KEY_REGISTRY_CONTRACT=$oprf_key_registry docker compose -f ./oprf-testnet-node/deploy/docker-compose.yml up -d oprf-key-gen0 oprf-key-gen1 oprf-key-gen2
    wait_for_health 20000 "oprf-key-gen0" 300
    wait_for_health 20001 "oprf-key-gen1" 300
    wait_for_health 20002 "oprf-key-gen2" 300

    echo -e "${GREEN}starting OPRF nodes..${NOCOLOR}"
    start_node 0
    start_node 1
    start_node 2
    wait_for_health 10000 "taceo-oprf-testnet-node0" 300
    wait_for_health 10001 "taceo-oprf-testnet-node1" 300
    wait_for_health 10002 "taceo-oprf-testnet-node2" 300

    echo -e "${GREEN}init OPRF keys for basic and wallet ownership modules..${NOCOLOR}"
    (cd contracts && OPRF_KEY_REGISTRY_PROXY=$oprf_key_registry OPRF_KEY_ID=1 forge script script/InitKeyGen.s.sol --broadcast --fork-url http://127.0.0.1:8545 --private-key $PK)
    (cd contracts && OPRF_KEY_REGISTRY_PROXY=$oprf_key_registry OPRF_KEY_ID=2 forge script script/InitKeyGen.s.sol --broadcast --fork-url http://127.0.0.1:8545 --private-key $PK)
    for i in 1 2; do
        wait_for_oprf_pub 10000 $i
        wait_for_oprf_pub 10001 $i
        wait_for_oprf_pub 10002 $i
    done
}

client() {
    cargo build --workspace --release
    ./target/release/taceo-oprf-testnet-client "$@"
}

main() {
    if [ $# -lt 1 ]; then
        echo "usage: $0 <command>"
        exit 1
    fi

    if [[ $1 = "setup" ]]; then
        echo -e "${GREEN}running setup..${NOCOLOR}"
        setup
        echo -e "${GREEN}press Ctrl+C to stop${NOCOLOR}"
        wait
    elif [[ $1 = "client" ]]; then
        echo -e "${GREEN}running client..${NOCOLOR}"
        client "${@:2}"
    elif [[ $1 = "test" ]]; then
        echo -e "${GREEN}running test..${NOCOLOR}"
        setup
        client --api-key foo --nodes http://127.0.0.1:10000,http://127.0.0.1:10001,http://127.0.0.1:10002 wallet-ownership
    else
        echo "unknown command: '$1'"
        exit 1
    fi
}

main "$@"
