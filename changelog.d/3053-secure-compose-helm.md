### Security
- **Compose and Helm can run on the secure baseline** (`admin validate
  --posture`: no deviations, file permissions included, #2922):
  `docker-compose.secure.yml` (backend TLS with a generated certificate that
  nginx verifies, rate limiting, `/metrics` token, a private 0600 config copy)
  and the chart's `secureBaseline.enabled` (Helm-generated certificates and
  token kept across upgrades, bundled Postgres over TLS, an initContainer that
  copies runtime files to 0600). Both need a server image newer than v0.95.3,
  so they are opt-in until the next release makes them the default. New
  `keyorix-server admin init --secure-files` (generate only the files an
  existing config references); the server image's entrypoint is now its
  ENTRYPOINT (`docker run <image> <cmd>` runs `<cmd>` after the config copy).
