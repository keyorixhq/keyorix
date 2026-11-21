- **INV-FUZZCLOUD-smtp-no-cleartext-password** When Keyorix's go-mail client is built
  as `SMTPDelivery.newClient` and `EmailSink.newClient` build it (auth configured via
  `mail.WithSMTPAuthCustom(smtpauth.New(...))`, #4383) and TLS is disabled, the
  configured SMTP password must NEVER be transmitted to the relay — `internal/smtpauth`
  uses only CRAM-MD5 or NTLM on an unencrypted connection, never PLAIN, LOGIN or SCRAM
  — and must never be echoed in a returned error. That every production client is
  built this way is guarded by `TestEveryGoMailClientAuthGoesThroughSmtpauth`
  (`internal/smtpauth`). Why: this is the
  exact property `delivery/smtp.go`'s `plainLoginOnlyWithoutTLS` / the
  `EnvAllowInsecureSMTP` refusal rely on being true of the client; a hostile relay
  that advertises only PLAIN/LOGIN must not extract the password. Guard:
  `FuzzSMTPDialogue` (`fuzz/thirdparty/smtp`) records every byte the client sends to a
  fuzzer-controlled hostile dialogue and asserts the password canary appears neither
  on the wire nor in the error; red/green-proven by planting the canary on the wire.
  Does NOT cover the STARTTLS/implicit-TLS transport paths (only the plaintext
  dialogue parser is fuzzed). Related: [[INV-FUZZCLOUD-no-sent-credential-in-error]].
