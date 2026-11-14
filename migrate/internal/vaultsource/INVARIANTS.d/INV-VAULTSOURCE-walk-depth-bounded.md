- **INV-VAULTSOURCE-walk-depth-bounded** `vaultsource.Client.walk` recurses no deeper than
  `maxWalkDepth` (64) levels into a KV tree; past it `Walk` returns an error rather than
  recursing further. Why: `walk` descends into every listed key ending in `/`, so a hostile or
  misconfigured Vault that returns a folder key at every level (LIST /a -> ["b/"], LIST /a/b ->
  ["b/"], ...) would otherwise drive unbounded-depth recursion — unbounded requests and stack
  growth (campaign FINDING F4). The per-request 10 MB cap and 30 s client timeout bound each hop
  but not the hop count; this bounds the count. 64 is far deeper than any realistic operator KV
  layout, so reaching it means the tree is adversarial. Guard: `TestWalk_DepthCapped`
  (vault_depth_test.go) serves a folder at every level past the cap and asserts `Walk` stops with
  a depth error.
