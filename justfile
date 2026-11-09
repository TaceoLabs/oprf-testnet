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

# Recompiles the circuits and copies the artifacts used by the node/client (requires the toolchain versions pinned in the artifacts).
[group('noir')]
noir-compile:
    cd noir/blinded_query_proof && nargo compile && cp target/blinded_query_proof.json ../../oprf-testnet-authentication/
    cd noir/verified_oprf_proof && nargo compile && cp target/verified_oprf_proof.json ../../oprf-testnet-authentication/

# Fails if the checked-in artifacts no longer match the noir sources.
# Only bytecode and ABI are compared; file_map/debug_symbols embed machine-specific paths.
[group('ci')]
noir-check-artifacts:
    cd noir/blinded_query_proof && nargo compile && diff <(jq '{abi,bytecode}' target/blinded_query_proof.json) <(jq '{abi,bytecode}' ../../oprf-testnet-authentication/blinded_query_proof.json)
    cd noir/verified_oprf_proof && nargo compile && diff <(jq '{abi,bytecode}' target/verified_oprf_proof.json) <(jq '{abi,bytecode}' ../../oprf-testnet-authentication/verified_oprf_proof.json)
