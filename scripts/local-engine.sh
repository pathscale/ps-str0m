#!/usr/bin/env bash
# Run a cargo command with the explicitly supplied local dependency patch.
#
# This is an opt-in development wrapper. Ordinary cargo commands use the
# published dependency versions from Cargo.toml. The local patch belongs in
# .cargo/local-engine.toml and is intentionally ignored by git.
#
# Examples:
#   scripts/local-engine.sh check -p str0m --no-default-features --features rust-crypto
#   scripts/local-engine.sh test -p str0m-rust-crypto

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo_dir="$root/.cargo"
config="$cargo_dir/local-engine.toml"
lock="$root/Cargo.lock"
guard="$cargo_dir/.local-engine.guard"
snapshot="$guard/Cargo.lock.snapshot"

if [[ ! -f "$config" ]]; then
    cat >&2 <<MSG
$config does not exist.

This wrapper is deliberately opt-in. Create that ignored file with only the
local path overrides you are actively working on, for example:

[patch.crates-io]
ps-str0m-rust-crypto = { path = "crypto/rust-crypto" }
str0m-proto = { path = "crates/proto" }

Ordinary cargo commands must continue to resolve published dependencies.
MSG
    exit 1
fi

if [[ "$#" -eq 0 ]]; then
    echo "usage: scripts/local-engine.sh <cargo-command> [args ...]" >&2
    exit 2
fi

mkdir -p "$cargo_dir"
if ! mkdir "$guard" 2>/dev/null; then
    echo "refusing concurrent local-engine invocation; guard exists: $guard" >&2
    echo "If no process owns it, inspect and remove that stale guard before retrying." >&2
    exit 1
fi

lock_was_present=0
snapshot_ready=0
if [[ -e "$lock" ]]; then
    lock_was_present=1
fi

cleanup() {
    status=$?
    trap - EXIT INT TERM

    if [[ "$snapshot_ready" -eq 1 ]]; then
        if ! cp -p "$snapshot" "$lock"; then
            echo "failed to restore $lock from $snapshot" >&2
            status=1
        fi
    elif [[ "$lock_was_present" -eq 0 ]]; then
        # Cargo may have created a redirected lockfile before a later failure.
        rm -f "$lock"
    fi

    rm -f "$snapshot" "$guard/pid"
    rmdir "$guard" 2>/dev/null || true
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ! printf '%s\n' "$$" > "$guard/pid"; then
    echo "failed to write the local-engine guard: $guard" >&2
    exit 1
fi

if [[ "$lock_was_present" -eq 1 ]]; then
    if ! cp -p "$lock" "$snapshot"; then
        echo "failed to snapshot $lock under $cargo_dir" >&2
        exit 1
    fi
    snapshot_ready=1
fi

cargo --config "$config" "$@"
