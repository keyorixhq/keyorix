### Fixed
- **Passkey `last_used_at` and core's default clock are UTC on a non-UTC host.** The WebAuthn counter write stored the caller's zone, and core's default clock returned host-zone times; both now return UTC (UTC-TOUCH-1).
