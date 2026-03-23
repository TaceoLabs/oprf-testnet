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
check-pr: lint all-rust-tests noir-tests setup-test

[group('ci')]
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-features --tests --examples --benches --bins -q -- -D warnings
    RUSTDOCFLAGS='-D warnings' cargo doc --workspace -q --no-deps --document-private-items

[group('local-setup')]
run-setup:
    @bash ./local-setup.sh setup

[group('tee')]
sync-allowed-vsock:
    @sudo bash -eu -c '\
        target_file="/etc/nitro_enclaves/vsock-proxy.yaml"; \
        [ -f "$target_file" ] || { echo "Missing $target_file" >&2; exit 1; }; \
        while IFS= read -r line || [ -n "$line" ]; do \
            [[ -z "${line//[[:space:]]/}" || "$line" =~ ^[[:space:]]*# ]] && continue; \
            grep -Fqx -- "$line" "$target_file" || printf "%s\n" "$line" >> "$target_file"; \
        done < allowed_vsock'

[group('test')]
setup-test:
    @bash ./local-setup.sh test

[group('client')]
run-client *args:
    @bash ./local-setup.sh client {{ args }}

[group('test')]
noir-tests:
    cd noir/blinded_query_proof && nargo test
    cd noir/verified_oprf_proof && nargo test

[group('tee')]
build-docker:
    docker build -t node -f build/Dockerfile.node .
    nitro-cli build-enclave --docker-uri node --output-file node.eif

[group('tee')]
run-enclave: killall build-docker
    nitro-cli run-enclave --eif-path node.eif --cpu-count 2 --memory 1024 --debug-mode > run_enclave.log

[group('tee')]
start-socats:
    pkill socat
    socat VSOCK-LISTEN:4444,fork,keepalive TCP:alchemy.com:443,keepalive &
    socat VSOCK-LISTEN:5432,fork,keepalive TCP:oprf-tee-testnet-2-cluster-prod.cluster-c1i26k0aa2nn.eu-central-1.rds.amazonaws.com:5432,keepalive &
    # socat TCP-LISTEN:8000,bind=0.0.0.0,fork,reuseaddr,keepalive VSOCK-CONNECT:42:4563,keepalive

[group('tee')]
killall:
    echo "Terminating all running enclaves..."
    nitro-cli terminate-enclave --all
