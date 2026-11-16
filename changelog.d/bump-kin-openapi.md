### Changed
- **Dependency bump: `github.com/getkin/kin-openapi` v0.152.0 to v0.153.0.** The release brings fuzz-found nil-dereference and validation fixes (multipleOf, pattern without type, external $ref errors) and decodes YAML natively through go.yaml.in/yaml/v4, so oasdiff/yaml and oasdiff/yaml3 leave go.mod.
