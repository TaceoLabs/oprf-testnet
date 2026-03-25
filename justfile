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
sync-allowed-vsock:
    @sudo bash -eu -c '\
        target_file="/etc/nitro_enclaves/vsock-proxy.yaml"; \
        [ -f "$target_file" ] || { echo "Missing $target_file" >&2; exit 1; }; \
        while IFS= read -r line || [ -n "$line" ]; do \
            [[ -z "${line//[[:space:]]/}" || "$line" =~ ^[[:space:]]*# ]] && continue; \
            grep -Fqx -- "$line" "$target_file" || printf "%s\n" "$line" >> "$target_file"; \
        done < allowed_vsock'

[group('tee')]
build-docker:
    docker build -t node -f build/Dockerfile.node .
    nitro-cli build-enclave --docker-uri node --output-file node.eif

[group('tee')]
run-enclave-debug: killall build-docker
    nitro-cli run-enclave --eif-path node.eif --cpu-count 2 --memory 1024 --debug-mode
    just start-socats

[group('tee')]
run-enclave: killall build-docker
    nitro-cli run-enclave --eif-path node.eif --cpu-count 2 --memory 1024 > enclave.log 
    just start-socats

[group('tee')]
start-socats: sync-allowed-vsock
    pkill socat || true
    socat VSOCK-LISTEN:4444,fork,keepalive TCP:alchemy.com:443,keepalive > alchemy.log 2>&1 &
    socat VSOCK-LISTEN:5432,fork,keepalive TCP:oprf-tee-testnet-${HOST_NR}-cluster-prod.cluster-c1i26k0aa2nn.eu-central-1.rds.amazonaws.com:5432,keepalive > db.log 2>&1 &
    socat VSOCK-LISTEN:4445,fork,keepalive TCP:crs.aztec.network:80,keepalive > crs.log 2>&1 &
    socat TCP-LISTEN:8000,bind=0.0.0.0,fork,reuseaddr,keepalive VSOCK-CONNECT:$(nitro-cli describe-enclaves | tr -d '\n' | sed -n 's/.*"EnclaveCID"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p'):4563,keepalive > listen.log 2>&1 &

[group('tee')]
killall:
    echo "Terminating all running enclaves..."
    nitro-cli terminate-enclave --all

[group('tee')]
nitrocli-debug:
    #!/usr/bin/env bash
    set -euo pipefail

    extract_enclave_id() {
        tr -d '\n' | sed -n 's/.*"EnclaveID"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
    }

    describe_output="$(nitro-cli describe-enclaves)"
    if [ "$(printf '%s' "$describe_output" | tr -d '[:space:]')" = "[]" ]; then
        just --justfile {{ justfile() }} run-enclave-debug
        describe_output="$(nitro-cli describe-enclaves)"
        enclave_id="$(printf '%s' "$describe_output" | extract_enclave_id)"
    else
        enclave_id="$(printf '%s' "$describe_output" | extract_enclave_id)"
    fi

    if [ -z "${enclave_id:-}" ]; then
        echo "Failed to determine enclave id." >&2
        exit 1
    fi
    echo "$enclave_id"
    nitro-cli console --enclave-id "$enclave_id"
