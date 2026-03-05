# Release Signing

## Keystore Generation

Generate a production keystore (do this once, store it securely outside the repo):

```bash
keytool -genkey -v \
  -keystore securecore-release.jks \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000 \
  -alias securecore \
  -storetype JKS
```

**NEVER commit the keystore file to the repository.**

Store the keystore in a secure location (e.g., 1Password, Google Cloud Secret Manager, or a hardware security module). If lost, you cannot publish updates to the same Play Store listing.

## Environment Variables

The build reads signing configuration from environment variables:

| Variable | Description |
|----------|-------------|
| `KEYSTORE_FILE` | Absolute path to the `.jks` keystore file |
| `KEYSTORE_PASSWORD` | Password for the keystore |
| `KEY_ALIAS` | Alias of the signing key (e.g., `securecore`) |
| `KEY_PASSWORD` | Password for the key alias |

### Local Development

Create a `local.properties` or export in your shell:

```bash
export KEYSTORE_FILE=/path/to/securecore-release.jks
export KEYSTORE_PASSWORD=your-store-password
export KEY_ALIAS=securecore
export KEY_PASSWORD=your-key-password
```

Then build the release APK/AAB:

```bash
cd android
./gradlew :app:bundleRelease
```

### CI (GitHub Actions)

Store secrets in GitHub repository settings:

1. Go to Settings > Secrets and variables > Actions
2. Add the following secrets:
   - `KEYSTORE_BASE64` — Base64-encoded keystore file (`base64 -i securecore-release.jks`)
   - `KEYSTORE_PASSWORD`
   - `KEY_ALIAS`
   - `KEY_PASSWORD`

In your workflow:

```yaml
- name: Decode keystore
  run: echo "${{ secrets.KEYSTORE_BASE64 }}" | base64 -d > /tmp/keystore.jks

- name: Build release AAB
  env:
    KEYSTORE_FILE: /tmp/keystore.jks
    KEYSTORE_PASSWORD: ${{ secrets.KEYSTORE_PASSWORD }}
    KEY_ALIAS: ${{ secrets.KEY_ALIAS }}
    KEY_PASSWORD: ${{ secrets.KEY_PASSWORD }}
  run: cd android && ./gradlew :app:bundleRelease
```

## Gradle Configuration

The `android/app/build.gradle.kts` reads from env vars:

```kotlin
signingConfigs {
    create("release") {
        val keystoreFilePath = System.getenv("KEYSTORE_FILE")
        if (keystoreFilePath != null) {
            storeFile = file(keystoreFilePath)
            storePassword = System.getenv("KEYSTORE_PASSWORD")
            keyAlias = System.getenv("KEY_ALIAS")
            keyPassword = System.getenv("KEY_PASSWORD")
        }
    }
}
```

If the env vars are not set (e.g., debug builds), the release signing config is skipped and a debug key is used instead.

## Versioning Convention

- `versionName` follows [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`
- `versionCode` is a monotonically increasing integer (required by Play Store)
- Both are bumped together using `scripts/bump-version.sh [major|minor|patch]`
- `versionCode` always increments by 1, regardless of the SemVer bump type

## Play App Signing

We recommend enrolling in [Play App Signing](https://developer.android.com/studio/publish/app-signing#app-signing-google-play). Google manages the release key, and you sign uploads with a separate upload key. This protects against keystore loss.
