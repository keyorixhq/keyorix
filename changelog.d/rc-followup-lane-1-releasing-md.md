### Changed
- **RELEASING.md "What the tag publishes" matches the workflows.** It now lists all six images (adds `keyorix-k8s-sync`, `keyorix-operator`, `keyorix-mcp`), all three signed Helm charts, the 32 release assets, the SLSA provenance and the nightly `main` image build, and points at `scripts/release/verify-release.sh`.

### Fixed
- **`verify-release.sh --self-test` failed on a clean clone** because the real v0.96.3 signing certificate fixture matched the `*.pem` gitignore rule; the public certificate is now committed and the self-test pins the 32-asset count.
