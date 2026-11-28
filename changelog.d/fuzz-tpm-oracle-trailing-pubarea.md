### Testing

- **TPM attestation fuzz oracle no longer flags a pubArea with trailing bytes.**
  `checkTPMAccepted` hashed and read the raw `pubArea`, while go-webauthn parses it
  with `tpm2.Unmarshal` (which ignores trailing bytes) and names the re-marshalled
  structure, so a statement with one extra byte after the TPMT_PUBLIC was reported as
  a Name mismatch although it attests the same key. The oracle now checks the Name and
  the key against the canonical form, and `TestTPMAttestation_TrailingPubAreaBytesTolerated`
  pins the library's tolerance. No product code changed.
