#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/bump-version.sh [major|minor|patch]
# Bumps versionName (SemVer) and auto-increments versionCode in android/app/build.gradle.kts

GRADLE_FILE="android/app/build.gradle.kts"
BUMP_TYPE="${1:-patch}"

if [[ ! -f "$GRADLE_FILE" ]]; then
    echo "Error: $GRADLE_FILE not found" >&2
    exit 1
fi

# Extract current values
CURRENT_CODE=$(grep -oP 'versionCode\s*=\s*\K\d+' "$GRADLE_FILE")
CURRENT_NAME=$(grep -oP 'versionName\s*=\s*"\K[^"]+' "$GRADLE_FILE")

if [[ -z "$CURRENT_CODE" || -z "$CURRENT_NAME" ]]; then
    echo "Error: Could not parse current version from $GRADLE_FILE" >&2
    exit 1
fi

# Parse SemVer
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_NAME"

case "$BUMP_TYPE" in
    major)
        MAJOR=$((MAJOR + 1))
        MINOR=0
        PATCH=0
        ;;
    minor)
        MINOR=$((MINOR + 1))
        PATCH=0
        ;;
    patch)
        PATCH=$((PATCH + 1))
        ;;
    *)
        echo "Usage: $0 [major|minor|patch]" >&2
        exit 1
        ;;
esac

NEW_NAME="$MAJOR.$MINOR.$PATCH"
NEW_CODE=$((CURRENT_CODE + 1))

# Update the file
sed -i.bak "s/versionCode\s*=\s*$CURRENT_CODE/versionCode = $NEW_CODE/" "$GRADLE_FILE"
sed -i.bak "s/versionName\s*=\s*\"$CURRENT_NAME\"/versionName = \"$NEW_NAME\"/" "$GRADLE_FILE"
rm -f "${GRADLE_FILE}.bak"

echo "Version bumped: $CURRENT_NAME (code $CURRENT_CODE) -> $NEW_NAME (code $NEW_CODE)"
