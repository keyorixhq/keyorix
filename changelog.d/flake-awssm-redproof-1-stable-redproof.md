### Testing
- **`TestAWSSMResponseFuzzO4RedProof` no longer flakes (FLAKE-AWSSM-REDPROOF-1).** The
  un-hardened half of the O4 red proof now serves its 3 x 64 MiB error body from an
  in-process `RoundTripper` (no socket, no server goroutine) and first asserts that the
  SDK consumed every wire byte before comparing the allocation with `awssmO4Budget`, so
  the budget and the assertion are unchanged and the proof still goes red when the oracle
  cannot catch an unbounded response. On loaded CI the real-socket version intermittently
  saw the client consume only 17-21 MB of 201 MB; a short read now fails with the consumed
  byte count instead of a misleading budget message.
