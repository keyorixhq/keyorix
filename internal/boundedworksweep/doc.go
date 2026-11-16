// Package boundedworksweep holds the committed, GREEN subset of the BW1
// ecosystem bounded-work sweep: bwgen-generated Fuzz targets (see
// scripts/fuzzing/bwgen) that assert a third-party or stdlib decoder's time and
// memory stay sub-super-linear vs input size, measured by
// internal/fuzzutil/boundedwork.
//
// Only targets that are GREEN on the pinned library version AND can reach a
// verdict live here. Each is a regression guard with a scripts/fuzzing/targets.d
// conf:
//
//   - bounded-work: json.Unmarshal (inputs scaled by boundedwork.ScaleJSONArray,
//     which keeps a valid document valid), yaml/v2 Unmarshal and UnmarshalStrict
//     (boundedwork.ScaleRepeat);
//   - round-trip: json and yaml/v2 Marshal/Unmarshal, decode-then-encode stable,
//     plus the same bounded-work check on the decode.
//
// A target is only a guard if at least one seed gets above the oracle's floors;
// TestBoundedWorkSweep_EveryTargetJudgesASeed holds that for every registered
// target. bwgen does not emit targets that cannot (reader-wrapping New*
// constructors, json.Valid; see unjudgeable in bwgen). Inputs that a target's
// scaler cannot grow into real work (for json, anything that is not valid JSON)
// are not judged. The FULL sweep (86 function targets + 8
// round-trip pairs across ~23 packages) is a reproducible research run, not
// committed wholesale: regenerate it with
//
//	go run scripts/fuzzing/bwgen/main.go -pkgs-file scripts/fuzzing/bwgen/sweep-pkgs.txt -out <scratch-dir>
//
// Targets that FIRED on their pinned version are NOT committed here (they would
// fail CI on their own seeds); they are recorded as findings in the BW1 report
// (the yaml.v3-family duplicate-key O(N^2) quadratic, F-YAML-DUPKEY). The files
// here carry bwgen's "DO NOT EDIT" header because they are verbatim generator
// output of
//
//	go run scripts/fuzzing/bwgen/main.go -pkgs encoding/json,go.yaml.in/yaml/v2 -out internal/boundedworksweep
//
// Running the full sweep into this directory would also drop the non-promoted
// targets in; emit that to a scratch dir instead.
package boundedworksweep
