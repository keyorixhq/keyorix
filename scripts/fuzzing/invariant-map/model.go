package main

// Data model for the invariant map. Everything here is plain data so the JSON
// output is stable: slices are sorted before emission and no timestamps are
// recorded.

// Def is one definition of an invariant ID in a doc (a legacy bullet in
// <pkg>/INVARIANTS.md or a fragment in <pkg>/INVARIANTS.d/).
type Def struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Fragment bool   `json:"fragment"`
	Section  string `json:"section,omitempty"`
	// Text is the full bullet text (not emitted in JSON; Statement is).
	Text string `json:"-"`
}

// Evidence is one check that references or declares coverage of an invariant.
type Evidence struct {
	Kind     string `json:"kind"`     // "fuzz" or "test"
	Strength string `json:"strength"` // fuzz: "strong" (named in a fuzz target/oracle) or "file" (same file as a fuzz target)
	Source   string `json:"source"`   // "ref" (ID appears in the check), "guard" (doc Guard: names it), "ledger"
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	Name     string `json:"name,omitempty"`
	// Registered is set for fuzz evidence: the Fuzz func is listed in targets.d.
	Registered *bool `json:"registered,omitempty"`
}

// Invariant is the merged record for one ID.
type Invariant struct {
	ID            string     `json:"id"`
	Area          string     `json:"area"`
	Section       string     `json:"section,omitempty"`
	Severity      string     `json:"severity"`
	SecurityScore int        `json:"security_score"`
	Statement     string     `json:"statement"`
	Class         string     `json:"class"`
	FuzzStrength  string     `json:"fuzz_strength,omitempty"`
	Defs          []Def      `json:"defs"`
	Evidence      []Evidence `json:"evidence,omitempty"`
	EvidenceTotal int        `json:"evidence_total"`
	Unguarded     bool       `json:"declared_unguarded,omitempty"`
	HasGuardText  bool       `json:"declares_guard,omitempty"`
	StaleChecks   []string   `json:"stale_checks,omitempty"`
	Flags         []string   `json:"flags,omitempty"`
}

// Class names.
const (
	ClassFuzz    = "COVERED-BY-FUZZ"
	ClassTest    = "COVERED-BY-TEST"
	ClassDocOnly = "DOC-ONLY"
)

// RefLoc is a source location of an ID mention.
type RefLoc struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// UnknownRef is an ID mentioned outside the definitions that no doc defines.
type UnknownRef struct {
	ID         string   `json:"id"`
	InCode     bool     `json:"in_code"`
	Refs       []RefLoc `json:"refs"`
	RefsTotal  int      `json:"refs_total"`
	Suggestion string   `json:"suggestion,omitempty"`
}

// Inconsistency describes an ID used inconsistently.
type Inconsistency struct {
	Kind   string   `json:"kind"`
	IDs    []string `json:"ids"`
	Detail string   `json:"detail"`
}

// LedgerRow is a row of an ADR-conformance / security-closure ledger.
type LedgerRow struct {
	Claim   string   `json:"claim"`
	File    string   `json:"file"`
	Tests   []string `json:"tests"`
	Class   string   `json:"class"` // FUZZ, TEST, MANUAL, STALE
	Missing []string `json:"missing,omitempty"`
}

// Summary holds the headline counts.
type Summary struct {
	Invariants   int            `json:"invariants"`
	ByClass      map[string]int `json:"by_class"`
	FuzzFileOnly int            `json:"fuzz_file_level_only"`
	WithStale    int            `json:"with_stale_checks"`
	Duplicates   int            `json:"duplicate_ids"`
	Unguarded    int            `json:"declared_unguarded"`
	Unknown      int            `json:"unknown_ids_referenced"`
	LedgerRows   int            `json:"ledger_rows"`
	LedgerStale  int            `json:"ledger_rows_stale"`
	FuzzTargets  int            `json:"fuzz_targets_registered"`
}

// AreaCount is a per-area class tally.
type AreaCount struct {
	Area    string `json:"area"`
	Total   int    `json:"total"`
	Fuzz    int    `json:"fuzz"`
	Test    int    `json:"test"`
	DocOnly int    `json:"doc_only"`
}

// Report is the full output.
type Report struct {
	Schema        int             `json:"schema"`
	Summary       Summary         `json:"summary"`
	ByArea        []AreaCount     `json:"by_area"`
	Invariants    []Invariant     `json:"invariants"`
	UnknownRefs   []UnknownRef    `json:"unknown_refs"`
	Inconsistency []Inconsistency `json:"inconsistencies"`
	IndexMismatch []string        `json:"index_mismatch,omitempty"`
	Ledger        []LedgerRow     `json:"ledger,omitempty"`
}
