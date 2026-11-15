### Tests
- **The stateful OpenAPI fuzzer no longer reports a secret's own read counter as a non-idempotent read.**
  Reading a secret increments `read_count` by design, so two back-to-back GETs differed in that one
  field and failed the idempotence oracle whenever the fuzzer drew such a pair (it failed unrelated
  pull requests' fuzz shard at random). The field is now stripped like the other volatile fields.
