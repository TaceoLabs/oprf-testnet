# [private]
default:
    @just --justfile {{ justfile() }} --list --list-heading $'Project commands:\n'

[group('test')]
unit-tests:
    cargo test --release --all-features --lib

[group('test')]
all-rust-tests:
    cargo test --release --workspace --all-features --all-targets

[group('ci')]
check-pr: lint all-rust-tests

[group('ci')]
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-features --tests --examples --benches --bins -q -- -D warnings
    RUSTDOCFLAGS='-D warnings' cargo doc --workspace -q --no-deps --document-private-items

[private]
prepare-localstack-secrets:
    AWS_ACCESS_KEY_ID=test \
    AWS_SECRET_ACCESS_KEY=test \
    aws --region us-east-1 --endpoint-url=http://localhost:4566 secretsmanager create-secret \
      --name oprf/eth/n0 \
      --secret-string '0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356' > /dev/null 2>&1 || true
    AWS_ACCESS_KEY_ID=test \
    AWS_SECRET_ACCESS_KEY=test \
    aws --region us-east-1 --endpoint-url=http://localhost:4566 secretsmanager create-secret \
      --name oprf/eth/n1 \
      --secret-string '0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97'> /dev/null 2>&1 || true
    AWS_ACCESS_KEY_ID=test \
    AWS_SECRET_ACCESS_KEY=test \
    aws --region us-east-1 --endpoint-url=http://localhost:4566 secretsmanager create-secret \
      --name oprf/eth/n2 \
      --secret-string '0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6' > /dev/null 2>&1 || true

[group('local-setup')]
run-setup:
    #!/usr/bin/env bash
    mkdir -p logs
    echo "starting localstack and anvil"
    docker compose -f ./oprf-testnet-node/deploy/docker-compose.yml up -d localstack anvil postgres oprf-node-db0 oprf-node-db1 oprf-node-db2
    sleep 1
    echo "preparing localstack"
    just prepare-localstack-secrets
    echo "starting OprfKeyRegistry contract.."
    just deploy-oprf-key-registry-with-deps-anvil | tee logs/deploy_oprf_key_registry.log
    oprf_key_registry=$(grep -oP 'OprfKeyRegistry proxy deployed to: \K0x[a-fA-F0-9]+' logs/deploy_oprf_key_registry.log)
    echo "oprf_key_registry=$oprf_key_registry"
    echo "register oprf-nodes..."
    OPRF_KEY_REGISTRY_PROXY=$oprf_key_registry just register-participants-anvil
    echo "starting OPRF key-gen instances..."
    OPRF_NODE_OPRF_KEY_REGISTRY_CONTRACT=$oprf_key_registry docker compose -f ./oprf-testnet-node/deploy/docker-compose.yml up -d oprf-key-gen0 oprf-key-gen1 oprf-key-gen2
    echo "starting OPRF nodes..."
    echo $oprf_key_registry
    OPRF_NODE_OPRF_KEY_REGISTRY_CONTRACT=$oprf_key_registry docker compose -f ./oprf-testnet-node/deploy/docker-compose.yml up -d oprf-node0 oprf-node1 oprf-node2
    sleep 40
    # OPRF_NODE_OPRF_KEY_REGISTRY_CONTRACT=$oprf_key_registry just run-nodes 
    echo "stopping containers..."
    docker compose -f ./oprf-testnet-node/deploy/docker-compose.yml down

[group('local-setup')]
run-nodes:
    #!/usr/bin/env bash
    mkdir -p logs
    cargo build -p taceo-oprf-testnet-node --release
    # anvil wallet 7
    # RUST_LOG="taceo_oprf_testnet_node=trace,taceo_oprf_service=trace,info,taceo_oprf_testnet_authentication=trace" ./target/release/oprf-testnet-node --bind-addr 127.0.0.1:10000 --db-connection-string postgres://postgres:postgres@localhost:5440/postgres --db-schema oprf --environment dev --version-req ">=0.0.0" > logs/node0.log 2>&1 &
    # pid0=$!
    # echo "started node0 with PID $pid0"
    # anvil wallet 8
    RUST_LOG="taceo_oprf_testnet_node=traceoprf_service_example=trace,warn" ./target/release/oprf-testnet-node --bind-addr 127.0.0.1:10001 --db-connection-string postgres://postgres:postgres@localhost:5441/postgres --db-schema oprf --environment dev --version-req ">=0.0.0" > logs/node1.log 2>&1 &
    pid1=$!
    echo "started node1 with PID $pid1"
    # anvil wallet 9
    RUST_LOG="taceo_oprf_testnet_node=trace,oprf_service_example=trace,warn" ./target/release/oprf-testnet-node --bind-addr 127.0.0.1:10002 --db-connection-string postgres://postgres:postgres@localhost:5442/postgres --db-schema oprf --environment dev --version-req ">=0.0.0" > logs/node2.log 2>&1  &
    pid2=$!
    echo "started node2 with PID $pid2"
    trap "kill $pid0 $pid1 $pid2" SIGINT SIGTERM
    wait $pid0 $pid1 $pid2

[group('dev-client')]
run-dev-client *args:
    #!/usr/bin/env bash
    cargo build -p taceo-oprf-testnet-dev-client --release
    oprf_key_registry=$(grep -oP 'OprfKeyRegistry proxy deployed to: \K0x[a-fA-F0-9]+' logs/deploy_oprf_key_registry.log)
    OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT=$oprf_key_registry ./target/release/taceo-oprf-testnet-dev-client {{ args }}

run-client *args:
    #!/usr/bin/env bash
    cargo build -p taceo-oprf-testnet-client --release
    RUST_LOG="taceo_oprf_testnet_client=trace,debug,info" ./target/release/taceo-oprf-testnet-client {{ args }}

[group('anvil')]
[working-directory('contracts/script/deploy')]
deploy-oprf-key-registry-with-deps-anvil:
    TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 THRESHOLD=2 NUM_PEERS=3 forge script OprfKeyRegistryWithDeps.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group('anvil')]
[working-directory('contracts/script/deploy')]
deploy-oprf-key-registry-anvil:
    TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 THRESHOLD=2 NUM_PEERS=3 forge script OprfKeyRegistry.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group('anvil')]
[working-directory('contracts/script')]
register-participants-anvil:
    PARTICIPANT_ADDRESSES=0x14dC79964da2C08b23698B3D3cc7Ca32193d9955,0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f,0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 forge script RegisterParticipants.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group('anvil')]
[working-directory('contracts/script')]
revoke-key-gen-admin-anvil:
    forge script RevokeKeyGenAdmin.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group('anvil')]
[working-directory('contracts/script')]
register-key-gen-admin-anvil:
    forge script RegisterKeyGenAdmin.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group('test')]
noir-tests:
    cd noir/blinded_query_proof && nargo test
    cd noir/verified_oprf_proof && nargo test
