- **INV-CORE-channel-guard-refuses-local-host** A notification-channel webhook/Slack
  destination never reaches the Keyorix host itself: `isChannelDisallowedIP` refuses
  loopback, the unspecified address (`0.0.0.0`, `::`) and the rest of `0.0.0.0/8`
  (Go's `net.Dial` treats an unspecified host as the local system; Linux routes a
  `connect()` to 0.0.0.0 to loopback), plus private and link-local ranges, directly
  and through every IPv6 embedding `netutil.EmbeddedIPv4` decodes. The one predicate
  backs all three checks: `validateWebhookURL` (create/update), the send-time
  `validateWebhookSendTimeURL` and the dial-time `escalationTransport`, so a stored
  URL, a DB-planted URL and a DNS answer that changes after the channel was saved
  are all held to it. Why: CodeQL #1209 triage (SECALERTS-PRODUCT-1) found
  `https://0.0.0.0:<port>/` and a name resolving to 0.0.0.0 connecting to loopback.
  Guard: `internal/core` `TestPostJSONToURL_UnspecifiedNeverReachesLoopback` (asserts
  no connection reaches a loopback listener), `TestIsChannelDisallowedIP_RefusesUnspecifiedAndThisNetwork`,
  `TestValidateWebhookURL_RefusesUnspecifiedLiteral`, `FuzzSSRFGuardDifferential`
  (encoding parity). **Not covered**: `FuzzSSRFGuardDifferential` skips `0.0.0.0/8`
  (its embedding collides with `::`/`::1`), so the unspecified range is pinned by the
  table tests above, not by the fuzzer; the sibling `notifychan`, `evidencesink` and
  SIEM guards permit loopback by design and are out of this invariant's scope.
