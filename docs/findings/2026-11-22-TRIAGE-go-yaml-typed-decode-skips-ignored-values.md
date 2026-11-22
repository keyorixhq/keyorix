# TRIAGE: go-yaml typed decode never constructs the value of a key that has no field — library design, Keyorix unaffected

**Status:** closed, triage only. No upstream report (decided 2026-11-22), no workaround, no
production change. The property "typed decode rejects what `any` decode rejects" is not one
go-yaml keeps, so no Keyorix fuzz target asserts it.

**Found by:** the multi-document and typed-decode fuzzing of YAML-V4-BASELINE-NOV-1 (#4611,
issue #4574), module `go.yaml.in/yaml/v4` v4.0.0.

## What happens

A struct decode skips a key that has no field without constructing its value. Checks that run
while a value is constructed (anchor self-reference, duplicate mapping keys) therefore never
run for it, so the typed decode accepts a document that an `any` decode refuses.

| input | `any` decode (v4) | typed decode into `config.Config` (v4) |
|---|---|---|
| `"&e \n0: *e"` (anchor cycle under an ignored key; seed `d880c7a036cd1909`) | `anchor 'e' value contains itself` | accepted |
| `": {s,s}"` (duplicate key `s` inside an ignored value; seed `17825f84d4209533`) | `mapping key "s" already defined at line 1` | accepted |

Both inputs are committed as seeds in `internal/config/testdata/fuzz/FuzzYAMLV4TypedDecode/`
and the target must pass them.

## v3 equals v4 (not a v4 regression)

Checked with a throwaway test (not committed) that decoded each input with `go.yaml.in/yaml/v3`
v3.0.6 (already an indirect dependency) and v4.0.0, into `any` and into `config.Config`:

| input | v3 `any` | v4 `any` | v3 typed | v4 typed |
|---|---|---|---|---|
| `&e \n0: *e` | `anchor 'e' value contains itself` | same, with `line 2:` | accepted | accepted |
| `zz: &e [*e]` | `anchor 'e' value contains itself` | same, with `line 1:` | accepted | accepted |
| `zz: {s: 1, s: 2}` | `mapping key "s" already defined at line 1` | same | accepted | accepted |
| `: {s,s}` | `did not find expected key` (parse error) | `mapping key "s" already defined` | `did not find expected key` | accepted |

The anchor case is identical in v3 and v4. For the second seed, v3's parser refuses the
flow-mapping form outright, so v3 never reaches the decode step; the same mechanism (duplicate
key under an ignored key) is identical in v3 and v4 when the input is spelled `zz: {s: 1, s: 2}`.
So the asymmetry is how go-yaml decodes into structs, not something v4 introduced.

## Keyorix exposure: none

An ignored value is never read. `config.Load` (and the k8ssync agent config, once #4617
lands) run the typed decode under `KnownFields(true)`, which rejects the unknown key itself (the key that has no
field), so such a document is refused for that reason before anything depends on it. Paths
that decode into a map (`secret import --format vault`) construct every value and so see both
checks. The duplicate-key pre-check in `internal/yamlsafe` works on the node tree and also
covers keys that no field would receive.

## What the fuzz target asserts instead

`FuzzYAMLV4TypedDecode` (internal/config): no panic, bounded work, a deterministic result (two
decodes of the same bytes give the same value or the same error text), and under KnownFields
an unknown top-level key is rejected, named in the error, with its value not echoed. It does
not assert "typed rejects what `any` rejects". `FuzzYAMLV4MultiDocument` keeps its document
count check and likewise leaves that property out.

## If this ever needs revisiting

Re-run the table above after a go-yaml bump. If typed decode starts rejecting these inputs the
seeds still pass (the target only requires no panic, determinism and the KnownFields property).
