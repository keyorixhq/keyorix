### Security
- **An encoded KEK file no longer leaves its text in process memory (#4498).** With the `file` key provider and a hex or base64 KEK file, the encoded KEK stayed in memory after `Shutdown`: in the file read buffer and in a string copy made while decoding. The read buffer is now wiped, the KEK is decoded without a string copy, and failed decode attempts are wiped too. Accepted file formats are unchanged. Raw KEK files were already wiped.

### Testing
- **Memory-residue oracle: encoded KEKs and the passphrase provider (#4498).** The oracle now also looks for the KEK's hex and base64 (standard and URL-safe) text and for the master passphrase. It runs one scenario each for raw, hex, base64 and URL-safe base64 KEK files and for the passphrase provider, with a separate ratchet per scenario. A new site-claims check, run with the GC off, fails if a copy allocated under `FileKeyProvider.KEK` survives `Shutdown` (`INV-ENCRYPTION-file-kek-read-wiped`).
