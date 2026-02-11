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

[group('dev-client')]
run-dev-client *args:
    @bash ./local-setup.sh client {{ args }}

[group('test')]
noir-tests:
    cd noir/blinded_query_proof && nargo test
    cd noir/verified_oprf_proof && nargo test
