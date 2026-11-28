- **INV-KDFMETER-compare-cost-ceiling** `CompareHashAndPassword` refuses a stored
  hash whose declared bcrypt cost exceeds `MaxCompareCost` (16) with
  `ErrHashCostTooHigh`, before any KDF work, and still notifies the observer exactly
  once. Keyorix hashes at cost 12, so a higher declared cost cannot come from this
  code; running it would cost 2^cost rounds (cost 31 is minutes of CPU per login
  attempt). Defence in depth: reaching it needs write access to the password-hash
  column or a foreign backup import. Guard: `TestCompareHashAndPassword_RefusesCostAboveCeiling`
  (read with a 5 s deadline, so red is a failure, not a hang),
  `TestCompareHashAndPassword_CeilingKeepsOneCountPerCall`,
  `TestCompareHashAndPassword_NormalHashesUnaffected`. Does not cover the cost
  `GenerateFromPassword` is asked for (callers pass `bcryptCost`, fixed at 12), and a
  malformed hash is passed through to bcrypt unchanged.
