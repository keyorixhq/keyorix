### Testing

- Added `fuzz/thirdparty/kinopenapi` full-document loader fuzz targets (KO3):
  `FuzzOpenAPIDocumentLoader` (bounded-work, load→marshal→load idempotence, and
  resolved-vs-JSON-round-trip differential over recursive/circular/deep/fan-out `$ref`
  graphs, extension fields and colliding names) and `FuzzOpenAPILoaderNoExternalRead`
  (an air-gap oracle proving `openapi3.Loader` with `IsExternalRefsAllowed=false` never
  reads a file or the network — hostile httptest server + `file://`/SSRF canaries +
  resguard NetMeter). Library-hardening only: Keyorix feeds this loader only the trusted
  build-time-embedded `openapi.yaml`; no production code changed.
