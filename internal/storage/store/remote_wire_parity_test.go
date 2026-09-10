// remote_wire_parity_test.go — every model that crosses the remote boundary is
// described TWICE by hand: a client-side `<x>Wire` in internal/storage/store,
// and a server-side `<x>ProxyWire` in server/http/handlers. Neither is generated
// and nothing made them agree, so a field added to one side (or to neither) is
// invisible until someone notices data missing in production.
//
// That is not hypothetical. #1573 added machine-caller attribution fields to
// five models; the wire structs were never updated, so every attribution field
// was silently dropped for `storage.type: remote` callers across MachineIdentity,
// SetupToken, ProjectMembership, ProjectInvitation and AccessReviewCampaign.
// A conformance campaign found them one model at a time, over ten agents, and
// still missed one — because enumeration finds instances and only derivation
// finds the set.
//
// Two independent properties are checked here, and BOTH are needed:
//
//  1. Attribution coverage — a *ByMachineIdentityID field on a model must
//     appear in the wire struct(s) for that model. Catches the #1573 shape,
//     where BOTH sides were missing the field and therefore agreed with each
//     other perfectly.
//  2. Client/server symmetry — paired wire structs must carry identical json
//     keys. Catches the SetupToken shape, where the server sent
//     created_by_machine_identity_id and the client silently ignored it.
//
// Check 2 alone would have passed the #1573 bugs; check 1 alone would have
// passed SetupToken. A guard that covers less than its name implies is worse
// than no guard, so the scope is stated plainly: this file verifies attribution
// fields and json-key symmetry. It does NOT verify that the wire structs carry
// every model field — some omissions are deliberate — nor that response
// envelopes match. Those are separate, real problems.
//
// See CLAUDE.md, "Core principle: prefer the machine-checked over the asserted."
package store

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	wireStructRe  = regexp.MustCompile(`(?ms)^type (\w*[Ww]ire) struct \{(.*?)^\}`)
	jsonTagRe     = regexp.MustCompile(`json:"([^",]+)`)
	attribFieldRe = regexp.MustCompile(`(?m)^\s*(\w+ByMachineIdentityID)\s`)
	modelStructRe = regexp.MustCompile(`(?m)^type (\w+) struct`)
)

type wireStruct struct {
	name  string
	file  string
	model string
	tags  map[string]bool
	body  string
}

// scanWires parses every `<x>Wire` struct in the given files and associates it
// with the model its constructor converts, when one is discoverable.
func scanWires(t *testing.T, glob string) map[string]wireStruct {
	t.Helper()
	files, err := filepath.Glob(glob)
	if err != nil {
		t.Fatalf("glob %s: %v", glob, err)
	}
	out := map[string]wireStruct{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f) // #nosec G304 -- fixed repo-relative globs
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		src := string(b)
		for _, m := range wireStructRe.FindAllStringSubmatch(src, -1) {
			name, body := m[1], m[2]
			tags := map[string]bool{}
			for _, tm := range jsonTagRe.FindAllStringSubmatch(body, -1) {
				tags[tm[1]] = true
			}
			ctor := regexp.MustCompile(`func new` + strings.ToUpper(name[:1]) + regexp.QuoteMeta(name[1:]) +
				`\(\w+ \*?models\.(\w+)\)`)
			model := ""
			if cm := ctor.FindStringSubmatch(src); cm != nil {
				model = cm[1]
			}
			out[name] = wireStruct{name: name, file: filepath.Base(f), model: model, tags: tags, body: body}
		}
	}
	return out
}

// modelAttributionFields returns model name -> the *ByMachineIdentityID fields
// declared on it. Derived from source, never from a list maintained here --
// a list is the thing this guard exists to make unnecessary.
func modelAttributionFields(t *testing.T) map[string][]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "models", "*.go"))
	if err != nil {
		t.Fatalf("glob models: %v", err)
	}
	out := map[string][]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f) // #nosec G304 -- fixed repo-relative glob
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		cur := ""
		for _, line := range strings.Split(string(b), "\n") {
			if m := modelStructRe.FindStringSubmatch(line); m != nil {
				cur = m[1]
			}
			if m := attribFieldRe.FindStringSubmatch(line); m != nil && cur != "" {
				out[cur] = append(out[cur], m[1])
			}
		}
	}
	return out
}

// TestRemoteWireCarriesAttributionFields is check 1 from this file's header.
func TestRemoteWireCarriesAttributionFields(t *testing.T) {
	t.Parallel()

	attribution := modelAttributionFields(t)
	if len(attribution) == 0 {
		t.Fatal("found no *ByMachineIdentityID fields on any model -- the scan has stopped " +
			"working and this guard is now vacuous; fix attribFieldRe, not the models")
	}

	client := scanWires(t, "remote_*.go")
	server := scanWires(t, filepath.Join("..", "..", "..", "server", "http", "handlers", "*_proxy.go"))
	if len(client) == 0 || len(server) == 0 {
		t.Fatalf("scanned %d client and %d server wire structs -- expected both to be non-zero; "+
			"the struct regex or the paths have drifted", len(client), len(server))
	}

	for _, side := range []struct {
		label string
		set   map[string]wireStruct
	}{{"client (internal/storage/store)", client}, {"server (server/http/handlers)", server}} {
		for _, w := range side.set {
			fields, ok := attribution[w.model]
			if !ok {
				continue // model carries no attribution fields; nothing to require
			}
			for _, f := range fields {
				if !strings.Contains(w.body, f) {
					t.Errorf("%s: %s (%s) mirrors models.%s but drops %s.\n"+
						"  Attribution fields record which machine identity performed an action (#1573). "+
						"Dropping one on the wire means every storage.type: remote caller loses that "+
						"audit attribution silently -- the read succeeds and the field is simply zero.\n"+
						"  Add the field to the struct AND to both conversion functions.",
						side.label, w.name, w.file, w.model, f)
				}
			}
		}
	}
}

// TestRemoteWireClientServerSymmetry is check 2 from this file's header.
func TestRemoteWireClientServerSymmetry(t *testing.T) {
	t.Parallel()

	client := scanWires(t, "remote_*.go")
	server := scanWires(t, filepath.Join("..", "..", "..", "server", "http", "handlers", "*_proxy.go"))

	byModel := map[string][2]*wireStruct{}
	for _, w := range client {
		if w.model == "" {
			continue
		}
		e := byModel[w.model]
		c := w
		e[0] = &c
		byModel[w.model] = e
	}
	for _, w := range server {
		if w.model == "" {
			continue
		}
		e := byModel[w.model]
		s := w
		e[1] = &s
		byModel[w.model] = e
	}

	paired := 0
	for model, pair := range byModel {
		c, s := pair[0], pair[1]
		if c == nil || s == nil {
			continue // only one side exists; nothing to compare
		}
		paired++
		onlyClient := diffKeys(c.tags, s.tags)
		onlyServer := diffKeys(s.tags, c.tags)
		if len(onlyClient) == 0 && len(onlyServer) == 0 {
			continue
		}
		t.Errorf("models.%s is described by two hand-written wire structs that disagree:\n"+
			"  client %s (%s)\n  server %s (%s)\n"+
			"  keys only on the client: %v\n  keys only on the server: %v\n"+
			"  A key present on one side and absent on the other is silently dropped in that "+
			"direction -- no error, just a zero value. Make both sides carry the same json keys.",
			model, c.name, c.file, s.name, s.file, onlyClient, onlyServer)
	}
	if paired == 0 {
		t.Fatal("no client/server wire pairs were found to compare -- this guard is vacuous; " +
			"the constructor regex used to associate a wire struct with its model has drifted")
	}
}

func diffKeys(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
