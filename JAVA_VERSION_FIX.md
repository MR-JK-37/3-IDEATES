# Java Version Compatibility Issue

## Problem
You're using **Java 25**, but React Native Android builds require **Java 17 or Java 21**.

## Solution Options

### Option 1: Install Java 17 or 21 (Recommended)

1. **Install Java 17 or 21:**
   ```bash
   # On Ubuntu/Debian
   sudo apt install openjdk-17-jdk
   # or
   sudo apt install openjdk-21-jdk
   ```

2. **Set JAVA_HOME:**
   ```bash
   # Find Java installation
   sudo update-alternatives --config java
   
   # Set JAVA_HOME (add to ~/.bashrc or ~/.zshrc)
   export JAVA_HOME=/usr/lib/jvm/java-17-openjdk
   # or
   export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
   ```

3. **Verify:**
   ```bash
   java -version  # Should show Java 17 or 21
   ```

4. **Run the app:**
   ```bash
   npm run android
   ```

### Option 2: Use SDKMAN (Easy Java Version Management)

```bash
# Install SDKMAN
curl -s "https://get.sdkman.io" | bash
source "$HOME/.sdkman/bin/sdkman-init.sh"

# Install Java 17
sdk install java 17.0.9-tem

# Use Java 17 for this session
sdk use java 17.0.9-tem

# Run the app
npm run android
```

### Option 3: Use Docker (Isolated Environment)

Create a Docker container with Java 17 and Android SDK.

## Quick Check

Check your current Java version:
```bash
java -version
```

If it shows Java 25 or higher, you need to downgrade to Java 17 or 21.

## Why This Happens

- React Native Android builds use Gradle
- Gradle 8.x supports Java 17-21
- Java 25 is too new and not yet supported
- The Android Gradle Plugin also requires compatible Java versions

## After Fixing

Once you have Java 17 or 21 installed and set as JAVA_HOME, run:
```bash
cd android
./gradlew clean
cd ..
npm run android
```
