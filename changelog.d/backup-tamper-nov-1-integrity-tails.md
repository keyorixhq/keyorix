### Security
- **`admin restore` now refuses a backup archive whose gzip checksum does not match.** The tar reader stops at the end-of-archive marker and skips entry padding without looking at it, so a flipped byte in tar padding or in the gzip trailer was accepted, and `scripts/airgap-e2e.sh` flaked on "admin restore accepted a tampered archive". `backupfmt.ExtractArchive` now reads the gzip stream to EOF after the last entry, so the CRC-32 and length are verified, and refuses on `gzip.ErrChecksum` or a damaged or truncated stream. The drain is capped at the restore's total-size limit, so trailing bytes after the tar end cannot be used as a decompression bomb. Guarded by `TestExtractArchive_RefusesGzipTamper`.

### Internal
- `scripts/dast/build-web-dist.sh` builds the dashboard with the same `node:22-alpine` digest as `server/Dockerfile` and `web/Dockerfile`.

### Testing
- `TestMySQLGuardAgreesWithDriver` now agrees with both go-sql-driver/mysql v1.10.1 and v1.10.2. The guard always refused a truncated error packet; only the test's expectation about the unguarded driver (fixed upstream in v1.10.2, go-sql-driver/mysql#1858) was version-specific, so a bump across that line failed it. The unguarded calibration now follows the driver version read from the test binary, and `TestMySQLDriverVersionReadable` stops it from skipping silently.
