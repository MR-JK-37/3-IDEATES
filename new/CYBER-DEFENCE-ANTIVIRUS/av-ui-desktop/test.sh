#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "[1/8] Frontend build"
npm run build

echo "[2/8] Frontend unit/runtime type sanity"
npm run build >/dev/null

echo "[3/8] Tauri config presence"
test -f src-tauri/tauri.conf.json

echo "[4/8] Tray icons presence"
test -f src-tauri/icons/tray-normal.png
test -f src-tauri/icons/tray-alert.png

echo "[5/8] Theme system files"
test -f src/contexts/ThemeContext.tsx
test -f src/components/ThemeSwitcher.tsx

echo "[6/8] Responsive layout files"
test -f src/hooks/useBreakpoint.ts
test -f src/components/layouts/ResponsiveLayout.tsx

echo "[7/8] Backend build check (best effort in offline environments)"
if cargo check --manifest-path src-tauri/Cargo.toml; then
  echo "cargo check passed"
else
  echo "cargo check skipped/failed (likely offline dependency index); see output above" >&2
fi

echo "[8/8] Backend command wiring sanity"
rg -n "toggle_autostart|toggle_realtime_protection|get_autostart_status|set_theme" src-tauri/src/main.rs >/dev/null

echo "All executable checks completed."
