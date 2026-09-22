# Tauri v1 to v2 Migration Checklist (CyberShield)

## Goal
Upgrade from Tauri v1 to v2 without breaking desktop releases, then enable full Android/iOS CI jobs.

## Current State
- Desktop release pipeline is production-safe.
- Mobile CI is gated and skipped while `tauri` major version is `1`.
- Gate is automatic in `.github/workflows/release.yml` via preflight detection.

## Step-by-step Migration
1. Upgrade JS packages in `av-ui-desktop/package.json`.
- Replace `@tauri-apps/api` v1 with v2.
- Replace `@tauri-apps/cli` v1 with v2.
- Run `npm install` and fix API import changes in frontend.

2. Upgrade Rust crates in `av-ui-desktop/src-tauri/Cargo.toml`.
- Upgrade `tauri-build` to v2.
- Upgrade `tauri` to v2.
- Reconcile feature flags (v2 uses different permission/capability model).

3. Migrate Tauri config.
- Convert `src-tauri/tauri.conf.json` to v2 schema.
- Add/update capability and permissions files required by v2.

4. Update command API usage.
- Verify `invoke` command names and payloads still map correctly.
- Re-test all desktop workflows and runtime features.

5. Initialize mobile projects.
- Run:
  - `npm run tauri android init`
  - `npm run tauri ios init`
- Commit generated mobile project scaffolding as needed.

6. Verify local builds before CI.
- Desktop: `npm run tauri build`
- Android: `npm run tauri android build --apk`
- iOS (macOS): `npm run tauri ios build -- --export-method ad-hoc`

7. Enable signing secrets in GitHub.
- Android keystore secrets.
- Apple notarization/signing credentials for iOS/macOS as needed.

8. Let CI auto-enable mobile.
- No workflow change required.
- `release.yml` preflight detects `tauri` major version.
- When major is `2`, mobile jobs run automatically.

## Safety Rules
- Keep desktop release paths green at every migration step.
- Merge v2 changes in small commits and validate `release.yml` after each.
- Do not remove mobile gating until end-to-end v2 mobile builds succeed.

## Rollback Plan
- Revert `package.json`, `Cargo.toml`, and `tauri.conf.json` to v1-compatible commits.
- Re-run desktop release workflow to confirm recovery.
