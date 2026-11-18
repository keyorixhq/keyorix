- **INV-LOG-event-redacts-both-formats** A recognisable secret (one whose form
  `Redact` claims to catch: a Keyorix `kx_*` token, a bearer value, a JWT, a PEM
  private key, a URL password, or a credential-like `key=value` such as
  `password=`/`client_secret=`/`api_key=`/`token=`) passed to `Event`/`Line` as
  the message or as a STRING kv value is replaced by `[REDACTED]` in BOTH text
  mode (`Redact(msg)` and `writeKV`'s `Redact`) and json mode (`eventJSON`'s
  string branch runs `Redact` before `json.Marshal`). Redaction of the Event path
  is therefore format-independent: the raw secret appears in NO format. This does
  NOT extend to non-string kv values (a map/slice is marshalled verbatim in json
  mode) nor to the raw `log.*` path (see INVARIANTS.md "Known boundaries").
  Why: an operator switching log format must not change whether a secret that
  reaches an `Event` call is scrubbed. Guard: `TestLG1_EventRedactsBothFormats_RedGreen`
  (red/green) and `FuzzLogRedaction` oracle O1 (every secret family, both
  formats) in `internal/logging/redaction_fuzz_test.go`.
