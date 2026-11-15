# Hostile-server fuzz harness: MongoDB Go driver v2

Attacks the real `go.mongodb.org/mongo-driver/v2` client (pinned v2.9.2 in the repo
`go.mod`) by driving it, through its **public API only** (`mongo.Connect` + `Ping` +
`Database().RunCommand()`), against a loopback server whose MongoDB wire-protocol
replies — message framing, `opCode`, `messageLength`, OP_MSG sections and the BSON
documents inside them — all come from the fuzz input. No Keyorix wrapper is in the
path, so a finding here is a driver bug reportable upstream.

Keyorix uses this driver in `internal/dynamic/mongodb.go` to connect to an
operator-configured target MongoDB and run `createUser` / `dropUser`. The untrusted
input modelled here is the **target server's replies** — the hostile- or
compromised-target threat (same family as the G48 DNS-rebinding guards).

## Handshake coverage

The fuzzer controls the reply to the connection handshake via a `mode` byte:

- **mode 0** — the first reply (to the driver's `hello`) is fuzzer bytes, fuzzing the
  wire-header + OP_MSG + hello-reply BSON decode path directly.
- **mode 1** — the first reply is a canned VALID `hello` (built with the real
  `bson.Marshal`), so the driver proceeds to SCRAM `saslStart`; every later reply is
  fuzzer bytes, fuzzing the sasl / command reply BSON path.

Auth cannot complete (the fake cannot forge a SCRAM proof), so the deterministic
oracle (d) test uses a **credential-free** client to give Ping a real
success/failure distinction; this isolates the wire reader, which is auth-independent.

## Run

```
go test ./fuzz/thirdparty/mongodb/ -count=1            # seeds + oracle red/green

GOMAXPROCS=2 nice -n 10 go test ./fuzz/thirdparty/mongodb/ \
    -run=xxx -fuzz=FuzzMongoReply -parallel=2 -fuzztime=10m
```

## Oracles

See the package doc comment in `fuzz_mongo_test.go` for the four oracle classes and
**exactly what each does not verify**. Host safety: the fuzzer-declared
`messageLength` is clamped to `maxWireLen` (64 KiB) before the bytes reach the driver
(the driver reads the whole wire message into one buffer sized by `messageLength` and
parses all BSON within it, so clamping the outer length bounds every allocation). The
uncapped pre-allocation behaviour is probed once by `TestWireLengthBound`.

## Files

- `fuzz_mongo_test.go` — the fuzz target, hostile server, wire/BSON reply builders.
- `oracle_mongo_test.go` — deterministic red/green oracle validation + findings repros.
- `testdata/fuzz/FuzzMongoReply/` — minimised crash/interesting inputs (if any).
