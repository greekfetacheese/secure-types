#!/usr/bin/env bash
#
# Runs the libFuzzer targets against the no_std + codec build, which is the build the
# fuzz package is declared against (see fuzz/Cargo.toml for why that is the one worth
# fuzzing). cargo fuzz needs a nightly toolchain: it builds with a sanitizer.
#
# Usage:
#   scripts/fuzz.sh                     smoke: 10 000 runs per target
#   scripts/fuzz.sh <target> [args...]  one target, arguments handed to libFuzzer
#   scripts/fuzz.sh --list              the target names
#
# A crash is written to fuzz/artifacts/<target>/. Reproduce it with
#   scripts/fuzz.sh <target> fuzz/artifacts/<target>/<crash file>
# and, once it is a regression test rather than a one-off, add the input to tests/.

set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

targets=(decode_secure_string decode_secure_bytes decode_vault vec_ops string_ops)

case "${1:-smoke}" in
   --list|list)
      printf '%s\n' "${targets[@]}"
      ;;
   smoke)
      for target in "${targets[@]}"; do
         echo "==> $target (smoke: 10 000 runs)"
         cargo +nightly fuzz run "$target" -- -runs=10000
      done
      ;;
   *)
      target="$1"
      shift
      if [ "$#" -gt 0 ]; then
         cargo +nightly fuzz run "$target" -- "$@"
      else
         cargo +nightly fuzz run "$target"
      fi
      ;;
esac
