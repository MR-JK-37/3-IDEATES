#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TARGET="${1:-all}"

build_desktop() {
  local target_name="$1"
  echo "Building desktop target: $target_name"
  npm run tauri build -- --target "$target_name"
}

build_mobile_android() {
  echo "Building Android APK/AAB"
  npm run tauri android init || true
  npm run tauri android build
}

build_mobile_ios() {
  echo "Building iOS bundle"
  npm run tauri ios init || true
  npm run tauri ios build
}

build_arch_package() {
  echo "Building Arch package via PKGBUILD workflow"
  if command -v makepkg >/dev/null 2>&1; then
    makepkg -f
  else
    echo "makepkg not installed; install base-devel to build Arch package" >&2
    return 1
  fi
}

case "$TARGET" in
  all)
    npm run tauri build
    build_desktop x86_64-pc-windows-msvc
    build_desktop x86_64-unknown-linux-gnu
    build_desktop universal-apple-darwin
    build_mobile_android
    build_mobile_ios
    build_arch_package
    ;;
  windows)
    build_desktop x86_64-pc-windows-msvc
    ;;
  linux)
    build_desktop x86_64-unknown-linux-gnu
    ;;
  macos)
    build_desktop universal-apple-darwin
    ;;
  android)
    build_mobile_android
    ;;
  ios)
    build_mobile_ios
    ;;
  arch)
    build_arch_package
    ;;
  *)
    echo "Usage: $0 [all|windows|linux|macos|android|ios|arch]" >&2
    exit 1
    ;;
esac
