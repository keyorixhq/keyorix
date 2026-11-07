# sdkdiff hostile-server mode

Extends the sdkdiff harness (see `../README.md`) with a mock server that
answers each SDK operation with a valid response and then applies one
structure-aware mutation, to see how the Go, Java, Node and Python SDKs
behave when the server sends malformed, oversized or slow responses.

Depends on the sdkdiff harness and drivers from PR #4035.

Rules, oracles, mutation catalogue and thresholds are pre-registered in
`RULES.md`; read it before interpreting any output.

## Usage

    go build -o sdkdiff ./scripts/e2e/sdkdiff
    sdkdiff hostile list                              # scenarios and mutations
    sdkdiff hostile run -sdks go,node,python,java \
        -sdks-dir <sdk checkout> -build <driver build dir> \
        -root . -out <dir> -mut C,N01,R -par 4
    sdkdiff hostile replay -triples sdk:scen:mut -n 3 ...
    sdkdiff hostile diff -base <dirA> -run <dirB> -sdk java
    sdkdiff hostile jsontable                         # decoder conformance table

Results: `results.jsonl` and `report.txt` in the output directory. Drivers run
niced, with bounded memory (RSS ceiling 1 GiB, 25 s wall clock per call).

## Validating the oracles

`plants/make-plants.sh` copies the SDK tree and applies small deliberate
defects (PH1..PH6; PH0 is a no-op control) to the copies only.
`validate.sh` runs the relevant subset against each copy and reports whether
the oracles flag it (DETECTED) and that the control stays silent.

## jsonparser/

Direct fuzzing of the Java SDK's hand-written `JsonParser` (Jazzer
standalone or a plain driver) against Gson in strict mode, plus conformance
tables for the Python, Node and Go decoders. Tool downloads are pinned by
SHA-256 in `fetch-tools.sh`; Gson/Jazzer are test-only and never enter the SDK
build.
