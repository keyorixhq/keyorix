### Testing
- **Leaf third-party library hostile-input fuzz targets.** Added
  `fuzz/thirdparty/gotpm` (`FuzzGoTPMUnmarshal`, google/go-tpm tpm2 wire
  (un)marshalling with a Marshal round-trip oracle, mapping to the sealed-blob
  decode in `internal/crypto/tpm_provider.go`), `fuzz/thirdparty/goi18n`
  (`FuzzGoI18nParseMessageFile`, nicksnyder/go-i18n message-file parsing),
  `fuzz/thirdparty/burnttoml` (`FuzzBurntTOML`, BurntSushi/toml round-trip) and
  further leaf-parser targets attacking the libraries' public APIs only. The TOML
  round-trip target found a real upstream non-idempotency defect (zone-less local
  date/time values drift by the host UTC offset on every decode→encode cycle on
  non-UTC hosts); its equality check is scoped around that known-open class.
  Keyorix is not exposed (it never round-trips TOML date/time values). Kept as
  regression tripwires.
