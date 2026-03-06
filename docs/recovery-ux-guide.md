# Recovery UX Guide

## Overview

This document describes the recommended user experience for the recovery bundle
export/import feature. The goal is to balance security with usability.

## Recovery Passphrase

### Generation

The app SHOULD offer two options:

1. **Generated passphrase (recommended)** — 12 words from the BIP39 English
   wordlist, displayed clearly to the user. This provides ~128 bits of entropy.
   Example: `abandon ability able about above absent absorb abstract absurd abuse access accident`

2. **User-chosen passphrase** — a free-form string chosen by the user.
   The app SHOULD enforce a minimum of 12 characters and display a strength
   indicator. Warn if the passphrase is weak.

### Display & Confirmation

- Display the passphrase in a large, monospace font with clear word boundaries.
- Group words in sets of 4 for readability (e.g., 4-4-4 layout).
- Ask the user to confirm by typing at least 3 randomly selected words.
- Provide a "Copy to clipboard" button with auto-clear after 60 seconds.
- Show a clear warning: **"Without this passphrase, your documents cannot be recovered."**

### Storage

- The app MUST NOT store the passphrase anywhere (not in preferences,
  not in keystore, not in the bundle).
- The passphrase exists only in memory during the export/import session.
- After the operation completes, zeroize the passphrase from memory.

## Export Flow

### Recommended UI Steps

1. **Select documents** — user picks which documents to include.
   Default: select all.

2. **Generate passphrase** — display the generated passphrase prominently.
   Show warning: "Write this down. Without it, your exported documents
   are permanently lost."

3. **Confirm passphrase** — ask user to re-enter or verify selected words.

4. **Export progress** — show a progress bar with document count.
   "Encrypting document 3 of 12..."

5. **Share bundle** — present the system share sheet (AirDrop, Files, etc.).
   Remind: "This file is encrypted. You can safely store it in the cloud."

### Error Handling

- If export fails mid-way, delete the partial bundle and show an error.
- If the user cancels, clean up immediately.

## Import Flow

### Recommended UI Steps

1. **Select bundle** — user picks the `.zip` file from Files, AirDrop, etc.

2. **Enter passphrase** — show a text field with word-by-word input
   (for BIP39) or a standard password field (for free-form).

3. **Verify** — attempt to unwrap the first DEK to validate the passphrase
   before proceeding with the full import. Show an error immediately if
   the passphrase is wrong: "Incorrect passphrase. Please try again."

4. **Import progress** — show progress: "Importing document 5 of 12..."

5. **Summary** — show results: "12 documents imported successfully."
   Warn about any skipped documents (e.g., duplicates).

### Error Handling

- Wrong passphrase: show error, allow retry. No limit on attempts
  (brute-force protection is via Argon2id computation cost).
- Corrupted bundle: "This bundle appears to be damaged. Some documents
  could not be imported."
- Duplicate documents: ask user whether to skip or overwrite.

## Security Warnings

Display these messages at appropriate points:

- **Before export**: "Your documents will be encrypted with a passphrase.
  Anyone with this passphrase can read your documents."
- **Passphrase display**: "Write this passphrase down and store it safely.
  Without it, your exported documents are permanently lost."
- **After export**: "The exported bundle is encrypted. You can safely
  store it in iCloud Drive, Google Drive, or any cloud service."
- **Before import**: "Enter the passphrase you received when this bundle
  was exported."

## Accessibility

- Passphrase words should be readable by screen readers.
- Use semantic labels: "Recovery word 1 of 12: abandon".
- Progress indicators should have accessibility descriptions.
- Error messages should be announced to VoiceOver/TalkBack.
