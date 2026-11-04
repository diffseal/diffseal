# Verify an evidence pack

## Install the CLI

```sh
npm install -g diffseal@beta
```

You can also install with Bun, Yarn or pnpm:

```sh
bun install -g diffseal@beta
yarn global add diffseal@beta
pnpm add -g diffseal@beta
```

The CLI needs Node.js 18 or later. For a one-off run without installing:

```sh
npx diffseal@beta verify ./pack --account your-org --period 2026-Q4
```

## Verify a pack

Extract the pack into a folder, then run:

```sh
diffseal verify ./pack --account your-org --period 2026-Q4
```

Verification runs offline. It checks the manifest format, the exact file set, every SHA-256 hash and the Ed25519 signature. It rejects symlinks, unsafe paths and duplicate paths, including names that differ only by case. It supports both `diffseal.pack/v2` and the free `diffseal.evidence-pack/v1` format.

The signing key id must match the public key and `pack.json`. Compromised keys always fail. A pack must have been generated at or after the key's `validFrom` and before its `revokedAt`, when set. `--account` checks the organisation login. `--period` checks the period label, such as `2026-Q4`.

The output shows the account, period, key id and file count. With the default keys, it also identifies the bundled key list, its update date and the [current published list](https://diffseal.com/.well-known/diffseal-keys.json). Since v0.5.0-beta the bundled list holds Diffseal's signing key, `d6ceaf99517d3d38`. A later key or a revocation reaches you in a new release, or through the published list with `--keys`.

You can provide a local list with `--keys public-keys.json`. The output identifies that file and its update date. It warns that this file is not Diffseal's published list. Obtain and authenticate it independently. The verifier never downloads keys.

## Verify without Node.js

If you cannot install Node.js, you can check a signed pack with standard tools: `shasum` or `sha256sum`, `find`, `sort`, `cut`, `diff`, `sed`, `base64` and OpenSSL 3.0 or later. The `openssl` that ships with macOS is LibreSSL, which cannot check an Ed25519 signature this way; use OpenSSL 3 (for example Homebrew's `openssl@3`) or a Linux machine.

Unzip the pack and run each step in the pack folder, the folder that holds `MANIFEST.sha256`.

1. Check every hash. Each line must end in `OK`.

   ```sh
   shasum -a 256 -c MANIFEST.sha256     # or: sha256sum -c MANIFEST.sha256
   ```

2. Check the file set. The manifest must list every file except `MANIFEST.sha256` and `signature.json`, and nothing else. Both commands must print nothing; the first finds symlinks and other files that are not regular files.

   ```sh
   find . ! -type f ! -type d
   find . -type f ! -path ./MANIFEST.sha256 ! -path ./signature.json | sed 's|^\./||' | LC_ALL=C sort > /tmp/pack-files.txt
   cut -c67- MANIFEST.sha256 | diff - /tmp/pack-files.txt
   ```

3. Take the public key. Find the `keyId` of `signature.json` in Diffseal's key list, [`keys/evidence-keys.json`](../../keys/evidence-keys.json) in this repository or the [published list](https://diffseal.com/.well-known/diffseal-keys.json), and copy its `publicKey`. The key id is the first 16 hex characters of the SHA-256 of the raw key, so the first command must print the key id that both files name.

   ```sh
   KEY='NFnZeLx1VeV95G3sSR+g9oooLnMlkaLA39LPvPWLlF4='    # publicKey of d6ceaf99517d3d38
   printf '%s' "$KEY" | base64 -d | shasum -a 256 | cut -c1-16    # or: sha256sum
   grep -o '"keyId" *: *"[^"]*"' signature.json pack.json
   ```

4. Check the signature. Diffseal signs the exact bytes of `MANIFEST.sha256` with Ed25519. `publicKey` is the raw 32-byte key in base64; `MCowBQYDK2VwAyEA` is the fixed header that turns it into a standard public key file. OpenSSL must print `Signature Verified Successfully`.

   ```sh
   printf -- '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA%s\n-----END PUBLIC KEY-----\n' "$KEY" > /tmp/diffseal-key.pem
   sed -n 's/.*"signature" *: *"\([^"]*\)".*/\1/p' signature.json | base64 -d > /tmp/pack-signature.bin
   openssl pkeyutl -verify -pubin -inkey /tmp/diffseal-key.pem -rawin -in MANIFEST.sha256 -sigfile /tmp/pack-signature.bin
   ```

   On macOS before 13, use `base64 -D`.

The signature covers the manifest and the manifest covers each file, so steps 1, 2 and 4 together show that the files are the ones Diffseal signed.

`diffseal verify` checks more than these commands do. Check the rest by reading the files:

| Check | `diffseal verify` | These steps |
| :-- | :-- | :-- |
| Hashes, file set, symlinks | Yes | Yes, steps 1 and 2 |
| Ed25519 signature over `MANIFEST.sha256` | Yes | Yes, step 4 |
| Key id matches the public key, `signature.json` and `pack.json` | Yes | Yes, step 3 |
| Key not compromised, `generatedAt` in `pack.json` at or after the key's `validFrom` and before its `revokedAt` | Yes | No. Read `compromised`, `validFrom` and `revokedAt` in the key list and compare them with `generatedAt` |
| Account and period | With `--account` and `--period` | No. Read `account.login` and `period.label` in `pack.json` |
| `pack.json` schema and `signing` (`Ed25519`, payload `MANIFEST.sha256`) | Yes | No. Read them in `pack.json` |
| Manifest format: UTF-8, sorted, final newline, no unsafe, duplicate or case-folded duplicate paths | Yes | In part. Step 2 fails on a listed path that is not a file in the folder, such as `../x`, but not on every malformed line |

For an unsigned free export, use:

```sh
diffseal verify ./export --allow-unsigned
```

This still checks the file set and hashes. It does not authenticate an author. A signature shows that the signed files have not changed. It does not prove that the analysis was correct or complete. Read the pack's coverage and analysis notes.

Exit code `0` means verification passed. Exit code `1` means it failed. Each failure appears on its own line. With `--json`, stdout contains `{ ok, failures, keyId?, account?, period?, files }`. Key provenance and the scope summary appear on stderr, so stdout remains valid JSON. `files` counts the regular payload files, excluding the manifest and signature.
