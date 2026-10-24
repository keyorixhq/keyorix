### Security

- **Notification-channel webhooks can no longer target the Keyorix host through 0.0.0.0.** The channel SSRF guard refused loopback but not the unspecified address, which Go dials as the local system: a channel URL of `https://0.0.0.0:<port>/…` or `https://[::]…`, or a hostname that resolves to 0.0.0.0 when an alert escalates, connected to the server's own loopback services. The guard now refuses `0.0.0.0/8` and `::` at create/update time, at send time and at dial time (found during the CodeQL #1209 triage).
