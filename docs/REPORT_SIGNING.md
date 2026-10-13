# Report Signing Trust

OpenVAPT signs reports with a local Ed25519 key. A valid signature proves that the report is unchanged since the holder of that key signed it. The public key embedded in the same report proves only self-consistency. It does not establish who the signer is.

To authenticate the signer, obtain the expected key ID through a separate trusted channel and run `openvapt verify report.json --key-id ID`. Back up the private key securely before rotating or reinstalling the machine. Distribute a new key ID through the same trusted channel after rotation.

The private key is stored at `$XDG_CONFIG_HOME/openvapt/report-key`, or under the operating system user configuration directory when that variable is unset. The containing directory is mode 0700 and the key is mode 0600. When OpenVAPT runs through `sudo`, the effective user is root, so the default key is normally `/root/.config/openvapt/report-key`, not the invoking user's key. Use consistent execution identity if reports must retain one signer identity.

Never send or embed the private key. Protect backups with access controls equivalent to the original mode 0600 file. If a key may have been copied or exposed, stop trusting its key ID, remove the old key, generate a new one on the next scan, and communicate the replacement ID through a trusted channel.
