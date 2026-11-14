- **INV-LIBCONF-mail-render-keeps-data-out-of-structure** A message wneessen/go-mail
  renders in internal/notifychan's shape (To from the recipient, Subject from the
  notification title, a text/plain body) has exactly a benign message's header fields;
  To and the envelope recipient parse back to the requested address with no CR, LF or
  NUL; the subject and the quoted-printable body decode back; the bytes use CRLF only
  and have no NUL. Two known library defects (an unbreakable long header word; the
  standard library quoted-printable writer dropping a line feed after CR and an escaped
  byte) are modelled exactly. Why: titles and bodies carry user-chosen text, which must
  never become a header (Bcc injection) or SMTP framing (smuggling). Guard:
  `internal/libconformance/gomail_render_fuzz_test.go:FuzzGoMailRenderRoundTrip`,
  `internal/libconformance/gomail_findings_test.go:TestGoMailFindingLongHeaderWord`,
  `internal/libconformance/gomail_findings_test.go:TestQPFindingStaleCR`.
<!-- section: Email rendering -->
