### Internal

- CI: the preflight job now runs `go mod tidy -diff` in every module of the repo (`GOWORK=off`), so a stale `// indirect` marker or a missing `require` fails the PR instead of surfacing later in a Dependabot update. `devtools/asymanalyzer/go.mod` and `go.sum` are tidied to match.
