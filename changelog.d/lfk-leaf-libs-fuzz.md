### Testing
- **Leaf third-party library hostile-input fuzz targets.** Added
  `fuzz/thirdparty/gotpm` (`FuzzGoTPMUnmarshal`, google/go-tpm tpm2 wire
  (un)marshalling with a Marshal round-trip oracle, mapping to the sealed-blob
  decode in `internal/crypto/tpm_provider.go`), `fuzz/thirdparty/goi18n`
  (`FuzzGoI18nParseMessageFile`, nicksnyder/go-i18n message-file parsing),
  `fuzz/thirdparty/burnttoml` (`FuzzBurntTOML`, BurntSushi/toml round-trip),
  `fuzz/thirdparty/gopsutil` (`FuzzGopsutilProc`, gopsutil/v4 /proc parsers via a
  fake HOST_PROC root), `fuzz/thirdparty/spf13pflag` (`FuzzPflagParse`, pflag
  argv parsing) — all attacking the libraries' public APIs only. Two known-open
  upstream robustness defects, recorded privately, are excluded from the oracles
  (temporal values in the TOML round-trip check, and `load.Avg` in the gopsutil
  target) so the targets stay green; Keyorix is not exposed to either. Kept as
  regression tripwires.
