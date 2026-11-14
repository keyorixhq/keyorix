// Package boundedworksweep holds the committed, GREEN subset of the BW1
// ecosystem bounded-work sweep: bwgen-generated Fuzz targets (see
// scripts/fuzzing/bwgen) that assert a third-party or stdlib decoder's time and
// memory stay sub-super-linear vs input size, measured by
// internal/fuzzutil/boundedwork.
//
// Only targets that are GREEN on the pinned library version live here — they are
// permanent regression guards (encoding/json, go.yaml.in/yaml/v2), each with a
// scripts/fuzzing/targets.d conf. The FULL sweep (86 function targets + 8
// round-trip pairs across ~23 packages) is a reproducible research run, not
// committed wholesale: regenerate it with
//
//	go run scripts/fuzzing/bwgen/main.go -pkgs-file scripts/fuzzing/bwgen/sweep-pkgs.txt -out <scratch-dir>
//
// Targets that FIRED on their pinned version are NOT committed here (they would
// fail CI on their own seeds); they are recorded as findings in the BW1 report
// (the yaml.v3-family duplicate-key O(N^2) quadratic, F-YAML-DUPKEY). The files
// here carry bwgen's "DO NOT EDIT" header because they are verbatim generator
// output; this directory is the curated promotion target, not bwgen's default
// out dir, so re-running bwgen into it would (intentionally) also drop the
// non-promoted targets back in — emit to a scratch dir instead.
package boundedworksweep
