#!/data/data/com.termux/files/usr/bin/bash
set -e

echo "Cleaning..."
rm -rf build
mkdir -p build/gen build/obj build/apk

# Locate Android JAR
PLATFORM_JAR="$HOME/.android/android.jar"
if [ ! -f "$PLATFORM_JAR" ]; then
    echo "Error: android.jar not found at $PLATFORM_JAR"
    exit 1
fi

echo "Compiling Resources (AAPT2)..."
# Compile layout
aapt2 compile --dir res -o build/resources.zip

# Link resources and generate R.java
aapt2 link -o build/apk/unaligned.apk \
    -I "$PLATFORM_JAR" \
    --manifest AndroidManifest.xml \
    --java build/gen \
    --auto-add-overlay \
    build/resources.zip

echo "Compiling Java (ECJ)..."
# Find all java files including the generated R.java
JAVA_FILES=$(find src build/gen -name "*.java")

ecj -d build/obj -classpath "$PLATFORM_JAR" -source 1.7 -target 1.7 $JAVA_FILES

echo "Dexing (D8)..."
d8 --lib "$PLATFORM_JAR" --output build/apk/ $(find build/obj -name "*.class")

echo "Packaging..."
# Start with the APK created by AAPT2
cp build/apk/unaligned.apk build/apk/final.apk

# Add the DEX file
cd build/apk
zip -uj final.apk classes.dex
cd ../..

# Add Assets (su, install.sh, nsenter)
# We zip them into the APK manually because aapt2 sometimes ignores raw files
zip -ur build/apk/final.apk assets

echo "Signing..."
apksigner sign --ks "$HOME/.android/debug.keystore" \
    --ks-pass "pass:android" \
    --key-pass "pass:android" \
    --out "build/RootManager.apk" \
    "build/apk/final.apk"

rm build/*.idsig

echo "DONE! APK is at build/RootManager.apk"
