### Testing
- **pkcs7 full-surface fuzz coverage (LS4).** Added harnesses for three more
  `github.com/digitorus/pkcs7` symbols: `(*PKCS7).UnmarshalSignedAttribute`
  (called for ContentType, MessageDigest, and SigningTime OIDs on arbitrary
  parsed envelopes), `(*PKCS7).GetOnlySigner`, and
  `(*SignedData).SignWithoutAttr` (legacy signing path that omits authenticated
  attributes). Coverage of the digitorus/pkcs7 exported surface rises from
  14/27 (LS3) to 17/27 symbols reached by at least one harness. All three
  harnesses passed 120 s foreground fuzz runs with no panics or hangs.
