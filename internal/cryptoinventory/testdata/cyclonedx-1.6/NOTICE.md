# Vendored CycloneDX 1.6 JSON schema

These files are verbatim copies of the official CycloneDX specification schemas, vendored so the
CBOM export test (`cbom_test.go`) validates offline and deterministically.

- Source: https://github.com/CycloneDX/specification (`schema/bom-1.6.schema.json`,
  `schema/spdx.schema.json`, `schema/jsf-0.82.schema.json`), retrieved 2026-10-23.
- License: Apache License 2.0 (see `LICENSE` in this directory; the schemas carry the same
  statement in their `$comment`). Redistribution with the license text is permitted.
- Do not edit these files. To update, replace all three from upstream together and re-run
  `go test ./internal/cryptoinventory`.
