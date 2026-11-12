- **INV-SPLITJSON-deterministic-bounded-explode** `Object(value)` is a pure, deterministic
  function of its bytes: two calls on identical input return byte-identical results. When it
  reports success (`ok == true`) every returned `Field` has a non-empty `Key` and a non-empty
  `Value`, the keys are strictly increasing (sorted, unique), and the total output size is
  bounded by `3×len(input)+64` (no unbounded amplification — the 3× accounts for
  encoding/json replacing each invalid-UTF-8 byte with the 3-byte U+FFFD). When it reports
  failure (`ok == false`) the returned slice is nil. A later import step derives each secret's
  Keyorix name from these keys and relies on the deterministic sorted order for idempotent
  re-runs. Why: hostile-source fuzzing of the migrate import path (task V2), the value is the
  first untrusted input a cloud source hands the tool. Guard: `FuzzSplitJSONObject`
  (splitjson_fuzz_test.go).
