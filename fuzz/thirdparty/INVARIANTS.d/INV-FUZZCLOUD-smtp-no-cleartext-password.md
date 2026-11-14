- **INV-FUZZCLOUD-smtp-no-cleartext-password** When Keyorix's go-mail client is built
  as `SMTPDelivery.newClient` builds it (auth configured via `SMTPAuthAutoDiscover`)
  and TLS is disabled, the configured SMTP password must NEVER be transmitted to the
  relay — go-mail drops PLAIN/LOGIN on an unencrypted connection rather than send a
  cleartext password, and must never be echoed in a returned error. Why: this is the
  exact property `delivery/smtp.go`'s `plainLoginOnlyWithoutTLS` / the
  `EnvAllowInsecureSMTP` refusal rely on being true of the library; a hostile relay
  that advertises only PLAIN/LOGIN must not extract the password. Guard:
  `FuzzSMTPDialogue` (`fuzz/thirdparty/smtp`) records every byte the client sends to a
  fuzzer-controlled hostile dialogue and asserts the password canary appears neither
  on the wire nor in the error; red/green-proven by planting the canary on the wire.
  Does NOT cover the STARTTLS/implicit-TLS transport paths (only the plaintext
  dialogue parser is fuzzed). Related: [[INV-FUZZCLOUD-no-sent-credential-in-error]].
