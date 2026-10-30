package config

import "github.com/keyorixhq/keyorix/internal/secretenv"

// secretSnapshot holds the *_FILE secrets Load read (secretenv.Snapshot): each
// source once per process, with the verdict on the descriptor it was read from.
// Process-wide because the accessors (SCIMConfig.GetToken, ...) have no *Config to
// hang it on and the environment it mirrors is process-wide too; an entry answers
// only while the environment still names the same file.
var secretSnapshot = secretenv.NewSnapshot()

// LookupSecretEnv is secretenv.Lookup answered from secretSnapshot: for a
// *_FILE secret Load took, the bytes of the descriptor the boot checks judged
// (live only for a name Load did not take). Server code that reads a secret
// config.Load names must use this, not secretenv.Lookup, which re-opens the file
// and could see a file the permission check never saw (#3830).
// TestNoLiveSecretenvLookupOfConfigSecrets enforces it.
func LookupSecretEnv(name string) (value string, found bool, err error) {
	return secretSnapshot.Lookup(name)
}

// snapshotSecrets records the non-key-material *_FILE secrets this config uses.
// Key material is read and judged by its own consumer (secretenv.LookupChecked)
// and is not kept.
func (c *Config) snapshotSecrets() {
	keyMaterial := map[string]bool{}
	for _, n := range c.keyMaterialSecretEnvNames() {
		keyMaterial[n] = true
	}
	var names []string
	for _, n := range c.secretEnvNames() {
		if !keyMaterial[n] {
			names = append(names, n)
		}
	}
	secretSnapshot.Take(names...)
}

// SecretFilePermissionProblems judges every file SecretFilePaths names by the
// key-material permission policy (secretenv's owner + mode rule) and returns one
// message per file that fails it: the *_FILE variable or config key, the path
// (through secretenv.DescribeFile, so a relative one is not shown) and the
// reason -- never the contents. keyProblems are the key-material secrets'. It
// applies no policy: EnforceSecretFilePermissions refuses or warns on the result,
// and `admin validate --posture` names the files in its deviation line (F7).
func (c *Config) SecretFilePermissionProblems() (problems, keyProblems []string) {
	keyMaterial := map[string]bool{} // the key-material secrets, by variable name
	for _, n := range c.keyMaterialSecretEnvNames() {
		keyMaterial[n] = true
	}
	// Each file is named by the variable or config key it came from, through
	// secretenv.DescribeFile (CheckPermissionsNamed): a relative path is never
	// shown, it may be the secret itself (SECRETENV-REVIEW-1 F4).
	seen := map[string]bool{}
	for _, fv := range secretenv.FileVars(c.secretEnvNames()...) {
		if seen[fv.Path] {
			continue
		}
		seen[fv.Path] = true
		// Judged on the descriptor the value was read from when the snapshot holds
		// it (F6: a separate stat could judge a different file than the one used);
		// key material and files the snapshot could not open are stat'd here.
		err, judged := error(nil), false
		if !keyMaterial[fv.Name] {
			err, judged = secretSnapshot.CheckPermissions(fv.Name)
		}
		if !judged {
			err = secretenv.CheckPermissionsNamed(fv.Var(), fv.Path)
		}
		if err != nil {
			if keyMaterial[fv.Name] {
				keyProblems = append(keyProblems, err.Error())
				continue
			}
			problems = append(problems, err.Error())
		}
	}
	for _, m := range []struct{ key, path string }{
		{"server.http.metrics_token_file", c.Server.HTTP.MetricsTokenFile},
		{"server.grpc.metrics_token_file", c.Server.GRPC.MetricsTokenFile},
	} {
		if m.path == "" || seen[m.path] {
			continue
		}
		seen[m.path] = true
		if err := secretenv.CheckPermissionsNamed(m.key, m.path); err != nil {
			problems = append(problems, err.Error())
		}
	}
	return problems, keyProblems
}
