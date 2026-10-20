#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ -z "${BPF_CLANG:-}" ]; then
 BPF_CLANG=clang
 for candidate in /opt/homebrew/opt/llvm/bin/clang /usr/local/opt/llvm/bin/clang; do
  if [ -x "$candidate" ]; then BPF_CLANG="$candidate"; break; fi
 done
fi
"$BPF_CLANG" -target bpfel -mcpu=v3 -O2 -g -fdebug-prefix-map="$(pwd)"=. -Wall -Werror -c internal/xdpguard/filter.c -o internal/xdpguard/filter.o
