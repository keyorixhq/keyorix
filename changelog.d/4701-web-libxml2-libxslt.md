### Security

- **Web image: libxml2 and libxslt pinned past four HIGH CVEs.** `web/Dockerfile` now requires libxml2 2.13.9-r3 or newer (CVE-2026-86144) and libxslt 1.1.43-r4 or newer (CVE-2026-125350, CVE-2026-87636, CVE-2026-9947), so the keyorix-web image passes the Trivy gate again.
