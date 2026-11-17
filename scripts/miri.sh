#!/usr/bin/env bash
#
# Runs Miri over the suites it can execute.
#
# Miri cannot run the default use_os build: its allocator is an mmap / memfd_secret
# region that is mlock'ed and mprotect'ed through libc, and Miri does not execute foreign
# functions. The no_std + alloc build keeps the same raw-pointer container code on the
# plain allocator, and tests/no_std.rs is the suite written for it.
#
# tests/codec.rs, tests/codec_decoder.rs and their siblings run on that build too, but
# they are sized for native throughput (a 10 000-element round trip, a 2 000-mutation
# corruption sweep) and one of them asserts a two-second wall-clock bound. Measured, the
# suite does not finish in minutes under Miri, so what runs here is the container suite —
# including its codec round trips — rather than the codec integration suites.
#
# Requirements: a nightly toolchain with the miri component.
#   rustup component add --toolchain nightly miri
#
# Usage: scripts/miri.sh [cargo miri test arguments...]
#
# Arguments are appended to a `--no-default-features` run: they select what is run,
# they do not re-enable the default `use_os` build. Forwarding them on their own would
# make `scripts/miri.sh --test no_std` run zero tests and exit 0, because all of
# tests/no_std.rs is gated on the absence of `use_os`.

set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

# Strict provenance makes a pointer that goes through usize and back a finding rather than
# a warning, which is what makes the raw-pointer arithmetic in SecureVec worth running
# under Miri. Isolation is left on: nothing here reads the clock, the environment or the
# filesystem.
export MIRIFLAGS="${MIRIFLAGS:--Zmiri-strict-provenance}"

if [ "$#" -gt 0 ]; then
   # `--no-default-features` is not optional here: the default build's allocator calls
   # libc, which Miri does not execute, and the suite it would select is gated on the
   # absence of `use_os`. Without it the run selects nothing and exits 0.
   echo "==> cargo +nightly miri test --no-default-features $*"
   exec cargo +nightly miri test --no-default-features "$@"
fi

echo "==> no_std + alloc: containers"
cargo +nightly miri test --no-default-features --test no_std

echo "==> no_std + alloc: containers, with the codec round trips"
cargo +nightly miri test --no-default-features --features codec --test no_std
