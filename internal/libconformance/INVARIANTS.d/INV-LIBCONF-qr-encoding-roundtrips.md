- **INV-LIBCONF-qr-encoding-roundtrips** Every symbol boombuler/barcode's QR encoder
  produces reads back, through an independent ISO/IEC 18004 decoder, to the requested
  content in the expected mode, with valid function patterns, BCH format and version
  information, zero Reed-Solomon syndromes and the minimal version; Encode fails only
  for content that is not encodable. The known numeric-mode sign defect is modelled
  exactly and is not reachable through an otpauth:// URL. Why: pquerna/otp's Key.Image
  renders enrolment QR codes with this encoder; a symbol that scans as different
  content enrols the wrong secret. Guard:
  `internal/libconformance/qr_roundtrip_fuzz_test.go:FuzzQRCodeRoundTrip`,
  `internal/libconformance/qr_findings_test.go:TestQRFindingNumericSign`.
<!-- section: QR rendering -->
