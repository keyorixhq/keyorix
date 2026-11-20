- **INV-LOG-injection-no-forge** Newline, CR, ANSI-escape, NUL, DEL and other
  control characters placed in the SANITISED positions — the request fields
  (`request_id`/`client_request_id`/`route`, each passed through `SanitizeID`,
  which keeps only printable ASCII) and kv VALUES (`writeKV` replaces `\n`/`\r`
  with a space; `eventJSON`/`json.Marshal` escapes them) — cannot: forge a second
  JSON record or a second text line, inject a top-level field, overwrite a
  reserved field (`ts`/`level`/`msg`/`request_id`/…), or be passed through the
  `jsonWriter` verbatim by forging the per-process random `lineMarker` nonce. Why:
  a request-scoped attacker-influenced value must be log DATA, never log
  STRUCTURE. Guard: `FuzzLogRedaction` oracle O3 (both formats) and
  `TestJSONMode_LogInjectionCannotForgeARecord` in `internal/logging`.
