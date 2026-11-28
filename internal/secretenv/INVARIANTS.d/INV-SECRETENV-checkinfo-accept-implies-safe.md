- **INV-SECRETENV-checkinfo-accept-implies-safe** When `checkInfo` / `CheckPermissions` /
  `CheckInfo` ACCEPTS a key-material file (returns `nil`), every condition the package doc
  states as always-refused holds: no setuid/setgid/sticky bit, no access for "other"
  (`perm&0o007==0`), no group-write (`perm&0o020==0`), a determinable owner that is the
  running euid or root, and -- if the file is group-readable/executable (`perm&0o050!=0`) --
  it is root-owned (not the running user) with a group the process holds. `CheckOwner`
  accepts only a determinable owner that is the running euid or root. Why: `secretenv.go`
  `CheckPermissions`/`CheckOwner`/`checkInfo` doc (#3393), the "Always refused" list.
  Guard: `FuzzCheckInfoNeverAcceptsUnsafe`, `FuzzCheckOwnerFailClosed` (one-directional:
  the accept-direction only; an over-strict refusal is not asserted). Does NOT cover the
  real-fstat/no-swap-window property of `OpenRegular` (own tests) nor the refusal error
  text (`TestCheckInfo_RefusesSpecialBitsGroupWriteAndOther`).
