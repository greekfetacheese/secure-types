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

set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

# Strict provenance makes a pointer that goes through usize and back a finding rather than
# a warning, which is what makes the raw-pointer arithmetic in SecureVec worth running
# under Miri. Isolation is left on: nothing here reads the clock, the environment or the
# filesystem.
export MIRIFLAGS="${MIRIFLAGS:--Zmiri-strict-provenance}"

if [ "$#" -gt 0 ]; then
   exec cargo +nightly miri test "$@"
fi

echo "==> no_std + alloc: containers"
cargo +nightly miri test --no-default-features --test no_std

echo "==> no_std + alloc: containers, with the codec round trips"
cargo +nightly miri test --no-default-features --features codec --test no_std
