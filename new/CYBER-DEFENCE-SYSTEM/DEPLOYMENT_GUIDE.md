# CyberDefense Pro - Deployment Guide

## Table of Contents

1. [Android (Google Play)](#android-google-play)
2. [iOS (App Store)](#ios-app-store)
3. [Windows (Microsoft Store / Direct)](#windows)
4. [macOS (App Store / Direct)](#macos)
5. [Linux (Package Managers)](#linux)
6. [Security & Code Signing](#security)

## Android (Google Play)

### Prerequisites

- Google Play Developer Account ($25 one-time fee)
- Keystore file for signing
- App meets Google Play policies

### Build Signed Release APK

```bash
cd mobile/android

# Generate keystore (one-time, keep secure)
keytool -genkey -v -keystore release.keystore \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -alias cybershield_release

# Build signed APK
./gradlew assembleRelease \
    -Pandroid.injected.signing.store.file=../../../release.keystore \
    -Pandroid.injected.signing.store.password=<PASSWORD> \
    -Pandroid.injected.signing.key.alias=cybershield_release \
    -Pandroid.injected.signing.key.password=<PASSWORD>

# Verify signing
jarsigner -verify -verbose app/build/outputs/apk/release/app-release.apk

# Optimize (optional but recommended)
zipalign -v 4 app/build/outputs/apk/release/app-release.apk \
    app-release-aligned.apk
```

### Upload to Google Play

1. Open Google Play Console
2. Create new app: "CyberDefense"
3. Fill app details:
   - Title: CyberDefense Pro
   - Category: Tools
   - Content Rating: Unrated (privacy focused)
4. Upload signed APK under "Release" → "Production"
5. Fill required info:
   - **Privacy Policy**: Link to privacy policy (required for permissions)
   - **Data Safety Form**: 
     - Declares NO data collection (all local)
     - Declares permissions usage
   - **Screenshots**: Upload 5+ screenshots
6. Review and submit

### Release Process

- Initial review: 2-4 hours typically
- Then available in Play Store for all users
- Updates similarly reviewed

## iOS (App Store)

### Prerequisites

- Apple Developer Account ($99/year)
- Xcode 14+
- iPhone with TestFlight app (for testing)
- App meets App Store Review Guidelines

### Build IPA

```bash
cd mobile/ios

# Install pods
pod install

# Build archive
xcodebuild \
    -workspace CyberDefense.xcworkspace \
    -scheme CyberDefense \
    -configuration Release \
    -derivedDataPath build \
    -destination generic/platform=iOS \
    archive -archivePath CyberDefense.xcarchive

# Export IPA
xcodebuild \
    -exportArchive \
    -archivePath CyberDefense.xcarchive \
    -exportOptionsPlist ExportOptions.plist \
    -exportPath build/Export
```

### Code Signing & Notarization

```bash
# Sign with Apple certificate (automatic via Xcode in most cases)

# For manual signing:
codesign -s "Apple Distribution" build/Export/CyberDefense.ipa

# Validate
codesign -v build/Export/CyberDefense.ipa
```

### Upload to App Store Connect

1. Open App Store Connect
2. Create new app: "CyberDefense"
3. Configure app:
   - Bundle ID: `com.cybershield.defense`
   - SKU: Choose unique identifier
   - Category: Utilities
   - Age Rating: Unrated/4+
4. Version Info:
   - Version Number: 1.0.0
   - Build: Upload IPA via Xcode or Transporter
   ```bash
   xcrun altool --upload-app --file CyberDefense.ipa \
       --type ios --apple-id <email> --password <app-password>
   ```
5. **Privacy & Safety**:
   - Privacy Policy URL (required)
   - Data Types Collected: None declared
   - Data Use Justification: Local-only security monitoring
6. **App Review Information**:
   - App functionality: Monitors device security threats locally
   - Sign in required: No
   - Testing notes: Document threat detection flow
7. Submit for Review

### App Store Review Guidelines (Important)

⚠️ **CyberDefense must comply with:**

- **4.3 Physical Threat**: App must not claim to prevent physical attacks
- **4.1.1 Illegal Activities**: Cannot monitor illegal use
- **5.1.1 Data & Privacy**: Must have privacy policy, cannot collect data
- **2.1 Beta Features**: Must be fully functional, not beta

### Timeline

- Submission review: 24-48 hours typically
- Standard apps under 5MB can go through expedited review
- Once approved, available worldwide in App Store

## Windows

### MSI Installer (Recommended)

```bash
cd desktop/native/windows

# Build
dotnet build -c Release -o bin/Release

# Create MSI using WiX Toolset (requires installation)
heat dir bin\Release -o files.wxs
candle files.wxs -o obj\files.wixobj
light obj\files.wixobj -o CyberDefense.msi

# Sign MSI (requires code signing certificate)
signtool sign /f certificate.pfx /p password /t http://timestamp.server \
    CyberDefense.msi
```

### Direct Distribution

1. Create `.zip` with executable
2. Sign code:
   ```bash
   signtool sign /f certificate.pfx /p password /t http://timestamp.server \
       CyberDefense.exe
   ```
3. Create installer with NSIS:
   ```bash
   makensis installer.nsi
   ```
4. Host on website
5. Create hash for integrity check:
   ```bash
   certutil -hashfile CyberDefense.exe SHA256
   ```

### Microsoft Store (Alternative)

1. Join Windows Dev Program
2. Create app submission in Partner Center
3. Upload MSIX/AppX package
4. Add screenshots, description
5. Set price (Free)
6. Submit for review

## macOS

### Direct Distribution

```bash
cd desktop/native/macos

# Build
xcodebuild -scheme CyberDefense -configuration Release \
    -derivedDataPath build

# Create DMG
hdiutil create -volname "CyberDefense" -srcfolder build/Release \
    -ov -format UDZO CyberDefense.dmg

# Code sign (requires Apple Developer Certificate)
codesign -s "Developer ID Application" build/Release/CyberDefense.app

# Notarize (required for Big Sur+)
xcrun notarytool submit CyberDefense.dmg \
    --apple-id <email> \
    --password <app-password> \
    --team-id <team-id> \
    --wait

# Staple notarization
xcrun stapler staple CyberDefense.dmg
```

### App Store (Mac App Store)

1. Create bundle with `.app` extension
2. Sign with Mac App Store certificate:
   ```bash
   codesign -s "3rd Party Mac Developer Application" \
       build/Release/CyberDefense.app
   ```
3. Create `.pkg` installer:
   ```bash
   productbuild --component build/Release/CyberDefense.app /Applications \
       --sign "3rd Party Mac Developer Installer" CyberDefense.pkg
   ```
4. Upload to App Store Connect
5. Submit for review

## Linux

### Debian Package (.deb)

```bash
# Build binary
cd desktop/native/linux
cargo build --release

# Create DEB structure
mkdir -p debian/DEBIAN
mkdir -p debian/usr/local/bin

# Copy binary
cp target/release/cyberdefense_linux_engine debian/usr/local/bin/

# Create control file
cat > debian/DEBIAN/control << EOF
Package: cyberdefense
Version: 1.0.0
Architecture: amd64
Maintainer: CyberDefense <support@cybershield.dev>
Description: CyberDefense Pro - Enterprise Cyber Defense
 Real-time threat detection for Linux systems
 - File monitoring with entropy detection
 - Process analysis
 - Network monitoring
EOF

# Build package
dpkg-deb --build debian cyberdefense_1.0.0_amd64.deb

# Sign (optional but recommended)
dpkg-sig -k <KEY-ID> -s builder cyberdefense_1.0.0_amd64.deb
```

### RPM Package (.rpm)

```bash
# Using FPM (Functional Package Manager)
fpm -s dir -t rpm -n cyberdefense -v 1.0.0 \
    --after-install scripts/post-install.sh \
    --before-remove scripts/pre-remove.sh \
    usr/local/bin/cyberdefense_linux_engine=/path/to/binary
```

### Distribution Methods

1. **PPA (Ubuntu)**
   ```bash
   # Create PPA at Launchpad
   dput ppa:username/ppa cyberdefense_1.0.0_source.changes
   ```

2. **AUR (Arch)**
   - Create `PKGBUILD` file
   - Submit to Arch User Repository
   - Users install with: `yay -S cyberdefense`

3. **Direct Download**
   - Host `.deb` and `.rpm` on website
   - Provide SHA256 checksums
   - Document installation: `sudo dpkg -i cyberdefense_1.0.0_amd64.deb`

4. **Package Managers**
   - Flathub (universal Linux)
   - Snap Store (Ubuntu)

## Security

### Code Signing Certificates

**Cost Overview:**
- **Windows**: $250-500/year
- **Apple**: $99/year (developer account) + certificate
- **Linux**: Free (GPG keys)

### Verification for Users

Provide checksums:
```bash
# Android APK
sha256sum app-release.apk

# iOS IPA
shasum -a 256 CyberDefense.ipa

# Windows MSI
certutil -hashfile CyberDefense.msi SHA256

# macOS
shasum -a 256 CyberDefense.dmg

# Linux
sha256sum cyberdefense_1.0.0_amd64.deb
```

### Privacy & Legal

1. **Privacy Policy** (required for all platforms):
   - Declare NO data collection
   - Explain local-only operation
   - List all permissions and why
   - GDPR/CCPA compliant

2. **Terms of Service**:
   - No liability for missed threats
   - User responsibility for device
   - No warranty

3. **Permissions Justification**:
   - **Android**: Declare why each permission needed in Google Play
   - **iOS**: Privacy labels for each API used
   - **macOS**: Entitlements for ES Framework
   - **Windows**: UAC prompt explanation

## Rollout Strategy

### Phase 1: Beta (1-2 weeks)
- Limited alpha/beta release
- TestFlight (iOS), Firebase (Android)
- Collect feedback and crash data
- Fix critical issues

### Phase 2: Staged Rollout (1-2 weeks)
- Roll out to 10% of users
- Monitor crash rates, reviews
- Expand to 50%, then 100%

### Phase 3: Monitoring
- Track crash rates
- Monitor user reviews
- Respond to issues promptly
- Plan version updates

## Version Updates

For subsequent releases:

```bash
# Increment version (1.0.0 → 1.0.1 for patches, 1.1.0 for features)
# Android: Update versionCode in build.gradle
# iOS: Update MARKETING_VERSION in Xcode
# Windows: Update version in .csproj
# macOS: Update CFBundleShortVersionString

# Build, sign, and submit following same process above
# Most platforms allow over-the-air updates

# For critical security patches: Fast-track review where available
```

## Monitoring Deployments

Post-launch:

1. **Crash Reporting**:
   - Firebase Crashlytics (mobile)
   - Sentry (desktop)
   - Monitor for regressions

2. **User Feedback**:
   - Review store ratings
   - Respond to reviews
   - GitHub issues for feature requests

3. **Metrics**:
   - Daily active users (DAU)
   - Retention curves
   - Feature adoption

---

**Version:** 1.0.0  
**Last Updated:** 2024
