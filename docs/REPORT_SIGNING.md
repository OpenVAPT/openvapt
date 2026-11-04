# Report Signing Trust

OpenVAPT signs reports with a local Ed25519 key. A valid signature proves that the report is unchanged since the holder of that key signed it. The public key embedded in the same report proves only self-consistency. It does not establish who the signer is.

To authenticate the signer, obtain the expected key ID through a separate trusted channel and run `openvapt verify report.json --key-id ID`. Back up the private key securely before rotating or reinstalling the machine. Distribute a new key ID through the same trusted channel after rotation.

The private key is stored at `$XDG_CONFIG_HOME/openvapt/report-key`, or under the operating system user configuration directory when that variable is unset. The containing directory is mode 0700 and the key is mode 0600. When OpenVAPT runs through `sudo`, the effective user is root, so the default key is normally `/root/.config/openvapt/report-key`, not the invoking user's key. Use consistent execution identity if reports must retain one signer identity.

Never send or embed the private key. Protect backups with access controls equivalent to the original mode 0600 file. If a key may have been copied or exposed, stop trusting its key ID, remove the old key, generate a new one on the next scan, and communicate the replacement ID through a trusted channel.

## Signature Format

The current format is `openvapt.sign/2`, recorded in the `format` field of the report's `integrity` block (`internal/sign/sign.go`). The block also holds the algorithm (`ed25519`), the SHA-256 digest, the public key, the key ID (the first 16 hex characters of SHA-256 of the public key) and the signature.

What is signed: the SHA-256 digest of the canonical JSON of the report without its `integrity` block (`report.CanonicalJSON`). `report.json` is written as that same canonical JSON with the block added, so the file itself is what the signature covers.

## Strict Verification

`openvapt verify report.json` checks the file exactly as stored:

- The file is decoded strictly. Unknown fields, duplicate keys and keys written in another letter case are refused (`internal/report/strict.go`). Files larger than 64 MiB are refused.
- The decoded report is turned back into canonical JSON, and the file must match it byte for byte. One trailing newline is allowed; any other difference, including reformatting, fails with "report file was modified after signing".
- The digest and the Ed25519 signature are then checked, and with `--key-id` the signing key must match the expected ID.

## Older Reports and Backward Compatibility

- Reports with an older report schema, such as `openvapt.report/2`, cannot be checked this way. Verification says "cannot verify: signed with an older report format" and asks you to re-run the scan with the current version. It never reports them as tampered.
- A report with the current schema whose `integrity` block has no `format` value is checked with the digest earlier builds used (the compact JSON of the report without the block), still subject to the strict, byte-exact file check.
- An unknown format value is refused with "cannot verify: unknown signature format".

## When Reports Are Not Signed

- `--no-sign` on `openvapt scan` and `openvapt demo` skips signing.
- If there is no per-user configuration folder (for example `HOME` is unset, or the folder path is not absolute), the report is written unsigned with a warning. OpenVAPT does not fall back to a shared folder such as `/tmp` for the private key.
- If the key folder or key file fails the protections below, the report is written unsigned with a warning that names the problem.

## Key File Protections

On Linux and other Unix systems the key folder must be a real directory (not a symlink), owned by the effective user, with no group or other permissions (mode 0700). The key must be a regular file (not a symlink), owned by the effective user, with no group or other permissions (mode 0600). A new key is created exclusively, without following symlinks, and the key is read without following symlinks. A key file that does not decode to a valid Ed25519 private key is reported as corrupt.

## Verifying a Downloaded Release

Report signing is separate from release signing. Every release binary carries a Sigstore bundle and a GitHub build provenance attestation from the release workflow. The installer always checks SHA-256, and checks the Sigstore signature when cosign is installed. Set `OPENVAPT_REQUIRE_SIGNATURE=1` to make the installer refuse to install when cosign is missing, instead of continuing with the checksum alone.

To check provenance yourself after downloading a binary, with the GitHub CLI:

```sh
gh attestation verify openvapt_linux_amd64 --repo OpenVAPT/openvapt \
  --signer-workflow OpenVAPT/openvapt/.github/workflows/release.yml
```

To check the Sigstore bundle with cosign:

```sh
cosign verify-blob --bundle openvapt_linux_amd64.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/OpenVAPT/openvapt/\.github/workflows/release\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com openvapt_linux_amd64
```

The installer accepts only HTTPS downloads (TLS 1.2 or newer, including redirects). `file://` locations are accepted only with `OPENVAPT_ALLOW_FILE=1`, which exists for offline tests.
