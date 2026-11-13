package k8ssync

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// FuzzConfigValidate drives the sync-agent config path (LoadConfig's parse+validate,
// minus the file read) with fuzzer-generated YAML. The agent sends KEYORIX_TOKEN as a
// bearer header to Config.KeyorixURL on every request and writes each mapping into a
// Kubernetes Secret, so a config that validate() ACCEPTS must satisfy the authorization
// and transport invariants the rest of the agent then trusts blindly:
//
//  1. CLEARTEXT GATE — KeyorixURL passes validateKeyorixURL (https, or http only to the
//     literal host "localhost"); never a cleartext token to a routable host.
//  2. PROJECT PINNING — ProjectID != 0 (every lookup is scoped to one project server-side;
//     a zero project id would be unscoped — see Config.ProjectID / #Bug1).
//  3. MAPPING SCOPE — every mapping has a non-empty Ref and a namespace/name/key that are
//     valid Kubernetes identifiers, so a mapping can never target a Secret outside a
//     well-formed (namespace, name, key) triple.
//  4. No panic on any YAML input.
//
// The oracle recomputes each property independently of validate()'s own control flow.
// What this does NOT verify: that the referenced secret or namespace actually exist or
// are permitted (that is server-side and cluster-side authz, not parseable here), nor
// anything about KEYORIX_TOKEN (read from the environment, not this file).
func FuzzConfigValidate(f *testing.F) {
	seeds := []string{
		"keyorix_url: https://keyorix.internal\nproject_id: 7\nmappings:\n  - ref: production/db\n    namespace: app\n    name: db-creds\n    key: password\n",
		"keyorix_url: http://localhost\nproject_id: 1\nmappings:\n  - ref: e/n\n    namespace: ns\n    name: s\n    key: k\n",
		"keyorix_url: http://127.0.0.1\nproject_id: 1\nmappings:\n  - ref: e/n\n    namespace: ns\n    name: s\n    key: k\n",
		"keyorix_url: https://x\nproject_id: 0\nmappings: []\n",
		"keyorix_url: ftp://x\nproject_id: 9\nmappings:\n  - ref: a/b\n    namespace: NS\n    name: s\n    key: k\n",
		"keyorix_url: https://x\nproject_id: 2\non_suspend: clear\nmappings:\n  - ref: a/b\n    namespace: n\n    name: s\n    key: ../etc\n",
		"not: valid: yaml: [",
		"keyorix_url: https://x\nproject_id: 3\ninterval: 5m\nmappings:\n  - ref: a/b\n    namespace: n\n    name: s\n    key: k\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		var c Config
		if err := yaml.Unmarshal(raw, &c); err != nil {
			return // not our concern: an unparseable config is rejected upstream.
		}
		if err := c.validate(); err != nil {
			return // rejected is safe.
		}

		// ACCEPTED. Independently re-check the load-bearing authz/transport invariants.
		if err := validateKeyorixURL(c.KeyorixURL); err != nil {
			t.Fatalf("validate() ACCEPTED a config whose keyorix_url %q FAILS the cleartext gate: %v",
				c.KeyorixURL, err)
		}
		if c.ProjectID == 0 {
			t.Fatalf("validate() ACCEPTED a config with project_id 0 — secret lookups would be unscoped (#Bug1)")
		}
		if len(c.Mappings) == 0 {
			t.Fatalf("validate() ACCEPTED a config with no mappings")
		}
		for i, m := range c.Mappings {
			if strings.TrimSpace(m.Ref) == "" {
				t.Fatalf("validate() ACCEPTED mapping %d with an empty ref", i)
			}
			if !isDNS1123Label(m.Namespace) {
				t.Fatalf("validate() ACCEPTED mapping %d with namespace %q that is not a valid RFC1123 label — "+
					"target namespace scope is undefined", i, m.Namespace)
			}
			if !isDNS1123Subdomain(m.Name) {
				t.Fatalf("validate() ACCEPTED mapping %d with Secret name %q that is not a valid RFC1123 subdomain", i, m.Name)
			}
			if !isK8sSecretKey(m.Key) {
				t.Fatalf("validate() ACCEPTED mapping %d with Secret data key %q outside [-._a-zA-Z0-9]+ (K8SSYNC-001)", i, m.Key)
			}
		}
	})
}
