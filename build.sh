#!/usr/bin/env bash
# Cross-compile sxfer + sxfer-mcp for every platform from one Linux box (or WSL) into dist/.
# Needs: rustup targets below, zig (`pip install ziglang`), cargo-zigbuild (`cargo install cargo-zigbuild`).
set -uo pipefail
cd "$(dirname "$0")"
. "$HOME/.cargo/env" 2>/dev/null || true
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/sxfer-target}"
VER=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
TARGETS=(
  x86_64-unknown-linux-musl     # Linux x86-64, fully static
  aarch64-unknown-linux-musl    # Linux ARM64 (Raspberry Pi 4/5, ARM servers), fully static
  x86_64-pc-windows-gnu         # Windows x86-64
  aarch64-pc-windows-gnullvm    # Windows on ARM
  x86_64-apple-darwin           # macOS Intel
  aarch64-apple-darwin          # macOS Apple Silicon
)
rm -rf dist && mkdir -p dist
fail=0
for t in "${TARGETS[@]}"; do
  printf '%-28s ' "$t"
  if cargo zigbuild --release --locked --target "$t" >"/tmp/sxfer-build-$t.log" 2>&1; then
    ext=""; [[ $t == *windows* ]] && ext=".exe"
    for bin in sxfer sxfer-mcp; do
      cp "$CARGO_TARGET_DIR/$t/release/$bin$ext" "dist/$bin-$VER-$t$ext"
    done
    echo "ok   $(du -h "dist/sxfer-$VER-$t$ext" | cut -f1) + $(du -h "dist/sxfer-mcp-$VER-$t$ext" | cut -f1)"
  else
    echo "FAILED (see /tmp/sxfer-build-$t.log)"; grep -m3 -E 'error' "/tmp/sxfer-build-$t.log"; fail=1
  fi
done
(cd dist && sha256sum sxfer-* > SHA256SUMS)
exit $fail
