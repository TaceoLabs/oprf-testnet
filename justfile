[private]
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
    docker compose -f ./oprf-testnet-service/deploy/docker-compose.yml up -d localstack anvil
    sleep 1
    echo "preparing localstack"
    just prepare-localstack-secrets
    echo "starting OprfKeyRegistry contract.."
    just deploy-oprf-key-registry-with-deps-anvil | tee logs/deploy_oprf_key_registry.log
    oprf_key_registry=$(grep -oP 'OprfKeyRegistry proxy deployed to: \K0x[a-fA-F0-9]+' logs/deploy_oprf_key_registry.log)
    echo "oprf_key_registry=$oprf_key_registry"
    echo "register oprf-nodes..."
    OPRF_KEY_REGISTRY_PROXY=$oprf_key_registry just register-participants-anvil
    echo "starting OPRF nodes..."
    OPRF_NODE_OPRF_KEY_REGISTRY_CONTRACT=$oprf_key_registry just run-nodes &
    echo "starting OPRF key-gen instances..."
    OPRF_NODE_OPRF_KEY_REGISTRY_CONTRACT=$oprf_key_registry just run-key-gen-instances
    echo "stopping containers..."
    docker compose -f ./oprf-testnet-service/deploy/docker-compose.yml down

[group('local-setup')]
run-nodes:
    #!/usr/bin/env bash
    mkdir -p logs
    cargo build -p taceo-oprf-testnet-service --release
    # anvil wallet 7
    RUST_LOG="taceo_oprf_testnet_service=trace,taceo_oprf_testnet_service_example=trace,oprf_service_example=trace,warn" ./target/release/oprf-testnet-service --bind-addr 127.0.0.1:10000 --rp-secret-id-prefix oprf/rp/n0 --environment dev --wallet-address 0x14dC79964da2C08b23698B3D3cc7Ca32193d9955 --version-req ">=0.0.0" > logs/node0.log 2>&1 &
    pid0=$!
    echo "started node0 with PID $pid0"
    # anvil wallet 8
    RUST_LOG="taceo_oprf_testnet_service=trace,taceo_oprf_testnet_service_example=trace,oprf_service_example=trace,warn" ./target/release/oprf-testnet-service --bind-addr 127.0.0.1:10001 --rp-secret-id-prefix oprf/rp/n1 --environment dev --wallet-address 0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f --version-req ">=0.0.0" > logs/node1.log 2>&1 &
    pid1=$!
    echo "started node1 with PID $pid1"
    # anvil wallet 9
    RUST_LOG="taceo_oprf_testnet_service=trace,taceo_oprf_testnet_service_example=trace,oprf_service_example=trace,warn" ./target/release/oprf-testnet-service --bind-addr 127.0.0.1:10002 --rp-secret-id-prefix oprf/rp/n2 --environment dev --wallet-address 0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 --version-req ">=0.0.0" > logs/node2.log 2>&1  &
    pid2=$!
    echo "started node2 with PID $pid2"
    trap "kill $pid0 $pid1 $pid2" SIGINT SIGTERM
    wait $pid0 $pid1 $pid2

[group('local-setup')]
[working-directory('/Users/guggi/Documents/projects/oprf-service/')]
run-key-gen-instances:
    #!/usr/bin/env bash
    mkdir -p logs
    # cargo build -p ../oprf-service/taceo-oprf-key-gen --release
    # anvil wallet 7
    RUST_LOG="taceo_oprf_key_gen=trace,warn" ./target/release/oprf-key-gen --bind-addr 127.0.0.1:20000 --rp-secret-id-prefix oprf/rp/n0 --environment dev --wallet-private-key-secret-id oprf/eth/n0 --key-gen-zkey-path ./circom/main/key-gen/OPRFKeyGen.13.arks.zkey --key-gen-witness-graph-path ./circom/main/key-gen/OPRFKeyGenGraph.13.bin  > logs/key-gen0.log 2>&1 &
    pid0=$!
    echo "started key-gen0 with PID $pid0"
    # anvil wallet 8
    RUST_LOG="taceo_oprf_key_gen=trace,warn" ./target/release/oprf-key-gen --bind-addr 127.0.0.1:20001 --rp-secret-id-prefix oprf/rp/n1 --environment dev --wallet-private-key-secret-id oprf/eth/n1 --key-gen-zkey-path ./circom/main/key-gen/OPRFKeyGen.13.arks.zkey --key-gen-witness-graph-path ./circom/main/key-gen/OPRFKeyGenGraph.13.bin  > logs/key-gen1.log 2>&1 &
    pid1=$!
    echo "started key-gen1 with PID $pid1"
    # anvil wallet 9
    RUST_LOG="taceo_oprf_key_gen=trace,warn" ./target/release/oprf-key-gen --bind-addr 127.0.0.1:20002 --rp-secret-id-prefix oprf/rp/n2 --environment dev --wallet-private-key-secret-id oprf/eth/n2 --key-gen-zkey-path ./circom/main/key-gen/OPRFKeyGen.13.arks.zkey --key-gen-witness-graph-path ./circom/main/key-gen/OPRFKeyGenGraph.13.bin  > logs/key-gen2.log 2>&1  &
    pid2=$!
    echo "started key-gen2 with PID $pid2"
    trap "kill $pid0 $pid1 $pid2" SIGINT SIGTERM
    wait $pid0 $pid1 $pid2

[group('dev-client')]
run-dev-client *args:
    #!/usr/bin/env bash
    cargo build -p taceo-oprf-testnet-dev-client --release
    oprf_key_registry=$(grep -oP 'OprfKeyRegistry proxy deployed to: \K0x[a-fA-F0-9]+' logs/deploy_oprf_key_registry.log)
    OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT=$oprf_key_registry ./target/release/taceo-oprf-testnet-dev-client {{ args }}

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
