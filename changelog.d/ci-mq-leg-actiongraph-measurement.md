### Internal
- **A verbose CI dispatch also records the Go build action graph per test leg (ci.yml).** With `workflow_dispatch` and `verbose_tests=true`, `go test` gets `-debug-actiongraph` and each leg uploads the JSON as an artifact, so the non-test part of a leg (compile, vet, link) can be split by measurement. Normal runs are unchanged.
