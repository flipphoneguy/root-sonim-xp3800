#!/usr/bin/env bash
set -euo pipefail

# --- read project.json ----------------------------------------------------
json_str() { sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' project.json | head -1; }
json_int() { sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' project.json | head -1; }

PKG=$(json_str package)
APP_NAME=$(json_str name)
MIN_SDK=$(json_int min_sdk)
TARGET_SDK=$(json_int target_sdk)

VERSION=$(cat VERSION | tr -d '[:space:]')
IFS='.' read -r V_MAJOR V_MINOR V_PATCH <<< "$VERSION"
VERSION_CODE=$((V_MAJOR * 10000 + V_MINOR * 100 + V_PATCH))

APK_NAME=$(echo "$APP_NAME" | tr -d ' ' | tr -cd 'A-Za-z0-9')
[ -z "$APK_NAME" ] && APK_NAME="App"

echo "=== Building $APP_NAME v$VERSION (code $VERSION_CODE) ==="
echo "    package: $PKG"

# --- check tools ----------------------------------------------------------
ANDROID_JAR="$HOME/.android/android.jar"
FRAMEWORK_RES="$HOME/.android/framework-res.apk"
KEYSTORE="$HOME/.android/debug.keystore"

for tool in aapt2 ecj d8 apksigner zip; do
    command -v "$tool" >/dev/null || { echo "ERROR: $tool not found"; exit 1; }
done
for f in "$ANDROID_JAR" "$FRAMEWORK_RES" "$KEYSTORE"; do
    [ -f "$f" ] || { echo "ERROR: $f not found"; exit 1; }
done

# --- prepare build dirs ---------------------------------------------------
rm -rf build
mkdir -p build/gen build/classes build/dex tmp

# --- sync manifest --------------------------------------------------------
sed -i "s/package=\"[^\"]*\"/package=\"$PKG\"/" AndroidManifest.xml
sed -i "s/android:versionCode=\"[^\"]*\"/android:versionCode=\"$VERSION_CODE\"/" AndroidManifest.xml
sed -i "s/android:versionName=\"[^\"]*\"/android:versionName=\"$VERSION\"/" AndroidManifest.xml
sed -i "s|android:authorities=\"[^\"]*\.fileprovider\"|android:authorities=\"$PKG.fileprovider\"|" AndroidManifest.xml

# --- generate BuildConfig.java --------------------------------------------
PKG_PATH=$(echo "$PKG" | tr '.' '/')
mkdir -p "build/gen/$PKG_PATH"
cat > "build/gen/$PKG_PATH/BuildConfig.java" <<JAVA
package $PKG;

public final class BuildConfig {
    public static final String VERSION_NAME = "$VERSION";
    public static final int VERSION_CODE = $VERSION_CODE;
    public static final String PACKAGE_NAME = "$PKG";
    public static final String APP_NAME = "$APP_NAME";
    public static final String REPO = "$(json_str repo)";
    public static final String GITHUB_PROFILE = "$(json_str github_profile)";
}
JAVA

# --- 1. compile resources -------------------------------------------------
echo "[1/5] compiling resources ..."
aapt2 compile --dir res/ -o build/resources.zip

# --- 2. link resources ----------------------------------------------------
echo "[2/5] linking resources ..."
aapt2 link \
    -o build/app_res.apk \
    --manifest AndroidManifest.xml \
    -I "$FRAMEWORK_RES" \
    --java build/gen \
    --min-sdk-version "$MIN_SDK" \
    --target-sdk-version "$TARGET_SDK" \
    --version-code "$VERSION_CODE" \
    --version-name "$VERSION" \
    build/resources.zip

# --- 3. compile java ------------------------------------------------------
echo "[3/5] compiling java ..."
find src -name '*.java' > build/sources.txt
find build/gen -name '*.java' >> build/sources.txt

CP="$ANDROID_JAR"
if [ -d libs ] && ls libs/*.jar 1>/dev/null 2>&1; then
    for jar in libs/*.jar; do CP="$CP:$jar"; done
fi

ecj \
    -cp "$CP" \
    -d build/classes \
    @build/sources.txt

# --- 4. dex ---------------------------------------------------------------
echo "[4/5] dexing ..."
CLASS_FILES=$(find build/classes -name '*.class')
D8_ARGS="--min-api $MIN_SDK --output build/dex --lib $ANDROID_JAR"
if [ -d libs ] && ls libs/*.jar 1>/dev/null 2>&1; then
    d8 $D8_ARGS $CLASS_FILES libs/*.jar
else
    d8 $D8_ARGS $CLASS_FILES
fi

# --- 5. package & sign ----------------------------------------------------
echo "[5/5] packaging & signing ..."
cp build/app_res.apk build/app_unsigned.apk
(cd build/dex && zip -j ../app_unsigned.apk classes.dex)
if [ -d assets ]; then
    zip -ur build/app_unsigned.apk assets/
fi

apksigner sign \
    --ks "$KEYSTORE" \
    --ks-key-alias androiddebugkey \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out "${APK_NAME}.apk" \
    build/app_unsigned.apk

rm -f "${APK_NAME}.apk.idsig"

SIZE=$(du -h "${APK_NAME}.apk" | cut -f1)
echo "=== done: ${APK_NAME}.apk ($SIZE) ==="
