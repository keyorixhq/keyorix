### Internal
- **pkcs7 API inventory (Stage 1 LS1).** `scripts/fuzzing/apigen/main.go` is a new portable go/types
  method walker that enumerates every exported symbol in a Go library, classifies parameters
  (`untrusted-bytes`/`structured`/`handle`/`config`), detects alloc-from-input and panic-by-contract,
  and emits a risk-ranked JSON inventory. `docs/fuzz/library-surface/api-inventory.json` and
  `API-INVENTORY.md` document the full 27-symbol surface of `github.com/digitorus/pkcs7` v0.0.0-20261104125046-a476de3098e4:
  1 of 27 covered (Parse, by 3 existing harnesses); top Stage 2 target is `(*PKCS7).VerifyWithOpts`
  (tier-1 Keyorix caller) and `(*PKCS7).DecryptUsingPSK` (untrusted PSK bytes).
  Portability confirmed on `github.com/google/uuid` v1.6.0 (59 symbols).
