### Testing
- **Leaf third-party library hostile-input fuzz targets.** Added
  `fuzz/thirdparty/gotpm` (`FuzzGoTPMUnmarshal`, google/go-tpm tpm2 wire
  (un)marshalling with a Marshal round-trip oracle, mapping to the sealed-blob
  decode in `internal/crypto/tpm_provider.go`), `fuzz/thirdparty/goi18n`
  (`FuzzGoI18nParseMessageFile`, nicksnyder/go-i18n message-file parsing),
  `fuzz/thirdparty/burnttoml` (`FuzzBurntTOML`, BurntSushi/toml round-trip),
  `fuzz/thirdparty/gopsutil` (`FuzzGopsutilProc`, gopsutil/v4 /proc parsers via a
  fake HOST_PROC root), `fuzz/thirdparty/spf13pflag` (`FuzzPflagParse`, pflag
  argv parsing) — all attacking the libraries' public APIs only. Two real upstream
  defects surfaced: BurntSushi/toml round-trips zone-less local date/time values
  non-idempotently (drift by host UTC offset per cycle on non-UTC hosts), and
  gopsutil/v4 `load.Avg` panics (index out of range) on a malformed `/proc/loadavg`
  with fewer than 3 fields. Both oracles are scoped around the known-open class so
  the targets stay green; Keyorix is not exposed to either (it never round-trips
  TOML date/time values and never calls `load.Avg`). Kept as regression tripwires.
