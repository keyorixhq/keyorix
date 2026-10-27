# Vendored Swagger UI

`swagger-ui.css`, `swagger-ui-bundle.js`, `swagger-ui-standalone-preset.js`, `LICENSE` and
`NOTICE` are byte-for-byte from the npm package `swagger-ui-dist@4.15.5` (Apache-2.0),
so `/swagger/` makes no request to a third-party host (air-gapped installs). Source maps
are not vendored; the `sourceMappingURL` comments are relative and only DevTools follows them.

`swagger-init.js` and `swagger-page.css` are Keyorix's own (the page cannot carry an inline
script or rely on a CDN under `script-src 'self'`).

SHA-256 pins are in `../swagger_test.go` (`TestSwaggerUIVendoredFilesArePinned`). To upgrade:
download the new `swagger-ui-dist`, replace the three files, update the version here and the
pins there. Nothing else references the version.
