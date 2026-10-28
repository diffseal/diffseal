# Verify an evidence pack

Extract the pack into a folder, then run:

```sh
diffseal verify ./pack --account your-org --period 2026-Q4
```

Verification runs offline. It checks the manifest format, the exact file set, every SHA-256 hash and the Ed25519 signature. It rejects symlinks, unsafe paths and duplicate paths, including names that differ only by case. Both `diffseal.pack/v2` and the free `diffseal.evidence-pack/v1` format are supported.

The signing key id must match the public key and `pack.json`. Compromised keys always fail. A pack must have been generated at or after the key's `validFrom` and before its `revokedAt`, when set. `--account` checks the organisation login. `--period` checks the period label, such as `2026-Q4`.

The output shows the account, period, key id and file count. With the default keys, it also identifies the bundled key list, its update date and the [current published list](https://diffseal.com/.well-known/diffseal-keys.json). Since v0.5.0-beta the bundled list holds Diffseal's signing key, `d6ceaf99517d3d38`. A later key or a revocation reaches you in a new release, or through the published list with `--keys`.

You can provide a local list with `--keys public-keys.json`. The output identifies that file and its update date. It warns that this file is not Diffseal's published list. Obtain and authenticate it independently. The verifier never downloads keys.

For an unsigned free export, use:

```sh
diffseal verify ./export --allow-unsigned
```

This still checks the file set and hashes. It does not authenticate an author. A signature shows that the signed files have not changed. It does not prove that the analysis was correct or complete. Read the pack's coverage and analysis notes.

Exit code `0` means verification passed. Exit code `1` means it failed. Each failure appears on its own line. With `--json`, stdout contains `{ ok, failures, keyId?, account?, period?, files }`. Key provenance and the scope summary appear on stderr, so stdout remains valid JSON. `files` counts the regular payload files, excluding the manifest and signature.
