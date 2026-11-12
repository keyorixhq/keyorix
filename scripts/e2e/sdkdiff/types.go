// Command sdkdiff is a cross-SDK differential fuzzer for the Keyorix client
// SDKs. See README.md and PREREGISTRATION.md.
package main

import (
	"encoding/json"
	"fmt"
)

// Arg is one operation argument: null, a string, or a reference to a value
// produced by an earlier step ("id" of an object result, "[0].id" of a list).
type Arg struct {
	Null bool
	Str  string
	Ref  *Ref
}

// Ref points into the result of an earlier step of the same scenario.
type Ref struct {
	Step int    `json:"step"`
	Path string `json:"path"`
}

// S builds a string argument.
func S(s string) Arg { return Arg{Str: s} }

// Null builds a null argument.
func Null() Arg { return Arg{Null: true} }

// MarshalJSON encodes null as null, strings as strings, refs as {"ref":{...}}.
func (a Arg) MarshalJSON() ([]byte, error) {
	switch {
	case a.Null:
		return []byte("null"), nil
	case a.Ref != nil:
		return json.Marshal(map[string]*Ref{"ref": a.Ref})
	}
	return json.Marshal(a.Str)
}

// UnmarshalJSON is the inverse of MarshalJSON.
func (a *Arg) UnmarshalJSON(b []byte) error {
	*a = Arg{}
	if string(b) == "null" {
		a.Null = true
		return nil
	}
	if len(b) > 0 && b[0] == '"' {
		return json.Unmarshal(b, &a.Str)
	}
	var m struct {
		Ref *Ref `json:"ref"`
	}
	if err := json.Unmarshal(b, &m); err != nil || m.Ref == nil {
		return fmt.Errorf("bad arg %s", string(b))
	}
	a.Ref = m.Ref
	return nil
}

// Fault is a proxy-side fault applied to the first Times requests of a step.
type Fault struct {
	Kind     string `json:"kind"`
	Status   int    `json:"status,omitempty"`
	Body     string `json:"body,omitempty"`
	Location string `json:"location,omitempty"`
	Ms       int    `json:"ms,omitempty"`
	Bytes    int    `json:"bytes,omitempty"`
	Times    int    `json:"times,omitempty"`
}

// Step is one SDK-level operation with its client configuration.
type Step struct {
	Op        string `json:"op"`
	Args      []Arg  `json:"args,omitempty"`
	Base      string `json:"base,omitempty"`  // plain|slash|slash2|upper_scheme|userinfo|query|fragment|prefix|literal:<url>
	Token     string `json:"token,omitempty"` // good|empty|canary|space|crlf|unicode|long
	TimeoutMs int    `json:"timeout_ms,omitempty"`
	Fault     *Fault `json:"fault,omitempty"`
	Expect    string `json:"expect,omitempty"` // "ok": the step is meant to succeed
}

// Scenario is a sequence of steps run against one fresh server state.
type Scenario struct {
	ID    string   `json:"id"`
	Tags  []string `json:"tags,omitempty"`
	Steps []Step   `json:"steps"`
}

// Rec is one request as the recording proxy saw it.
type Rec struct {
	Method     string              `json:"method"`
	RequestURI string              `json:"request_uri"`
	Header     map[string][]string `json:"header"`
	Body       []byte              `json:"body,omitempty"`
	BodyCut    bool                `json:"body_cut,omitempty"`
	Faulted    string              `json:"faulted,omitempty"`
	RespStatus int                 `json:"resp_status"`
	RespBody   string              `json:"resp_body,omitempty"`
}

// StepOutcome is what one SDK did for one step.
type StepOutcome struct {
	Drv  map[string]any `json:"drv"`
	Reqs []Rec          `json:"reqs"`
}

// Outcome is one SDK's run of one scenario.
type Outcome struct {
	SDK    string        `json:"sdk"`
	Steps  []StepOutcome `json:"steps"`
	Failed string        `json:"failed,omitempty"` // harness artifact (H1): driver crash, hang, protocol error
	Token  string        `json:"-"`                // session token of this SDK's server instance (E3 check)
}

// Finding is one discrepancy found by an oracle.
type Finding struct {
	Cat       string     `json:"cat"`
	Op        string     `json:"op"`
	Step      int        `json:"step"`
	Blocks    [][]string `json:"blocks"` // SDK partition
	Shape     string     `json:"shape"`  // root-cause shape used for de-duplication
	Detail    string     `json:"detail"`
	ScenarioI string     `json:"scenario"`
}

// Sig is the de-duplication signature of a finding.
func (f Finding) Sig() string {
	return fmt.Sprintf("%s|%s|%s|%s", f.Cat, f.Op, blocksString(f.Blocks), f.Shape)
}

func blocksString(b [][]string) string {
	s := ""
	for i, blk := range b {
		if i > 0 {
			s += "/"
		}
		for j, n := range blk {
			if j > 0 {
				s += ","
			}
			s += n
		}
	}
	return s
}
