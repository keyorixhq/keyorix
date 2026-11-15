### Testing
- **Leaf third-party library hostile-input fuzz targets.** Added
  `fuzz/thirdparty/gotpm` (`FuzzGoTPMUnmarshal`, google/go-tpm tpm2 wire
  (un)marshalling with a Marshal round-trip oracle, mapping to the sealed-blob
  decode in `internal/crypto/tpm_provider.go`) and further leaf-parser targets
  attacking the libraries' public APIs only. No library defects found over the
  recorded runs; kept as regression tripwires.
