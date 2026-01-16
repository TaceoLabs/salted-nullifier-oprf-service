[private]
default:
    @just --justfile {{ justfile() }} --list --list-heading $'Project commands:\n'

[group('ci')]
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --tests --examples --benches --bins -q -- -D warnings
    RUSTDOCFLAGS='-D warnings' cargo doc --workspace -q --no-deps --document-private-items
