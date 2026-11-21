# KEK lock split step 1 — design decision

**Date:** 2026-11-21  
**Branch:** `fuzz/v3-kek-lock-split-step1`  
**Issue:** #4376  
**Design doc:** `docs/design/2026-11-15-key-custody-availability.md` §2

## Decision: approach (b) — full `rotateMu + atomic.Pointer[keyState]`

### Approach (a) ruled out: deadlock

Approach (a) — keep `mu sync.RWMutex` for DEK-lineage fields, add an atomic for
KEK-derived fields only — requires `RotateKEKPassphrase` to briefly take
`mu.Lock()` at the end (to update `dekSnapshot`) without holding it during the
fsync. This creates a deadlock with `RewrapDEKWithPrepare`:

1. Rewrap: takes `mu.Lock()`, calls `acquireExclusiveKeyLock()` → waits for flock
2. KEK rotation: holds flock, then needs `mu.Lock()` for `dekSnapshot` → waits
3. **Deadlock.**

No variant of approach (a) that leaves `RewrapDEK` holding `mu.Lock()` for the
flock acquisition avoids this. Moving `dekSnapshot` to an atomic requires the
same full migration as approach (b).

### Approach (b): `rotateMu + atomic.Pointer[keyState]`

**`keyState` struct** (immutable after publish):
```
currentDEK, dekSnapshot, keyVersion,
evidenceSignKey, evidenceSignKeyID,
auditCheckpointKey, auditCheckpointKeyID,
backupManifestKey, backupManifestKeyID
```

**Lock split:**
- `rotateMu sync.Mutex`: serialises all three rotation operations and
  Initialize/Wipe within this process. Readers never take it.
- `state atomic.Pointer[keyState]`: published by `state.Store()` after all
  durable I/O completes; readers use `state.Load()` with no lock.

**What is NOT changed:**
- `RewrapDEK` and `RotateDEKWithSweep` still hold `rotateMu.Lock()` for their
  entire duration including fsyncs (identical behaviour, different lock name).
- Cross-process flock (`acquireExclusiveKeyLock`) is still acquired inside the
  rotation lock, as before.
- `RotateDEKWithSweep`'s sweep scope, ordering, and crash-consistency invariants
  are unchanged.

**Wipe trade-off for `RotateKEKPassphrase`:**
The old `keyState`'s signing-key bytes (`evidenceSignKey`, `auditCheckpointKey`,
`backupManifestKey`) are not immediately wiped after `state.Store()` because
concurrent readers may still hold the old pointer. They are released to GC.
`RotateDEKWithSweep` and `RewrapDEK` wipe the old `currentDEK` immediately after
`state.Store()` because the server is stopped for both (exclusive key lock).
Design doc §2.5 explicitly accepts the GC-release approach for the signing keys.

**Fields NOT in `keyState`** (remain on the struct):
- `dekPath`, `saltPath`, `baseDir`, `configErr`, `keySet` — config, immutable after construction
- `keyProvider` — set before Initialize, read under `rotateMu`

## Scope boundary note

Approach (b) mechanically changes all three rotation methods. Readers are no
longer blocked during Rewrap/Sweep's fsyncs either — this is a side-effect of the
shared-state design. The DURATION of the lock held by Rewrap and Sweep is
unchanged (they hold `rotateMu.Lock()` for the same scope as they previously held
`mu.Lock()`). Step 2 (narrow Rewrap's lock further) and step 3 (narrow Sweep) are
unchanged in scope and require separate go-aheads.
