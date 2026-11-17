### Testing
- Added a cross-release configuration-compatibility fuzz harness
  (`scripts/fuzzing/configcompat`, `FuzzConfigCompat`) that takes configuration
  files shipped by earlier releases and differentially checks them against the
  current loader: an old file must still load or be refused with an error that
  names the offending key, an accepted configuration must not hold a
  security-relevant posture that no explicit setting or documented default
  explains, and a deprecated setting name must keep its original meaning and warn
  when used. Harness-only; no shipped code changed.
