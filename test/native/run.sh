#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
# Intentional word splitting for compiler flags from pkg-config and CFLAGS.
# shellcheck disable=SC2046,SC2086
${CC:-cc} -std=c11 -g -O1 -Wall -Wextra -Werror -pthread \
  ${CFLAGS:-} $(pkg-config --cflags openssl) \
  test/native/bio_frag_test.c $(pkg-config --libs openssl) \
  -o "$build_dir/bio_frag_test"
"$build_dir/bio_frag_test" concurrent
for step in 1 2 3 4 5 6 7; do
  "$build_dir/bio_frag_test" method-failure "$step"
done
"$build_dir/bio_frag_test" context-failure
for step in 0 1 2 3 4; do
  "$build_dir/bio_frag_test" ssl-failure "$step"
done
"$build_dir/bio_frag_test" srtp-failure
"$build_dir/bio_frag_test" boundaries
