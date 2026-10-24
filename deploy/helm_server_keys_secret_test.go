package deploy

import (
	"strings"
	"testing"
)

// keysSecretSets is Secret mode (server.keysSecret, docs/multi-replica-keys.md).
var keysSecretSets = []string{
	"server.keysSecret.enabled=true",
	"server.keysSecret.name=keyorix-keys-1",
	"server.keysPersistence.enabled=false",
}

func podSpec(t *testing.T, docs []map[string]any) map[string]any {
	t.Helper()
	dep := findDoc(docs, "Deployment", "server")
	if dep == nil {
		t.Fatal("no server Deployment")
	}
	spec, _ := nested(dep, "spec", "template", "spec").(map[string]any)
	return spec
}

func namedItem(list any, name string) map[string]any {
	items, _ := list.([]any)
	for _, it := range items {
		m, _ := it.(map[string]any)
		if m["name"] == name {
			return m
		}
	}
	return nil
}

// Secret mode, the supported HA mode: the key files are copied from the Secret
// into a memory emptyDir by an init container (0600, the server's uid) and the
// server mounts that READ-ONLY; no keys PVC; key_dir_lock: database. Checked for
// two replicas and for one (the opt-in), with and without secureBaseline.
func TestHelmKeysSecret_RendersReadOnlyKeysFromTheSecret(t *testing.T) {
	requireHelm(t)
	for _, tc := range []struct {
		name string
		sets []string
	}{
		{"two replicas", append(keysSecretSets, "server.replicas=2")},
		{"one replica, opted in", keysSecretSets},
		{"two replicas, secureBaseline off", append(keysSecretSets, "server.replicas=2", "secureBaseline.enabled=false")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			docs := haDocs(t, tc.sets...)
			if findDoc(docs, "PersistentVolumeClaim", "") != nil {
				t.Error("Secret mode must not render a keys PVC")
			}
			for _, d := range docs {
				if d["kind"] == "PersistentVolumeClaim" {
					t.Errorf("Secret mode rendered a PersistentVolumeClaim: %v", d["metadata"])
				}
			}
			spec := podSpec(t, docs)

			server := namedItem(spec["containers"], "server")
			keysMount := namedItem(server["volumeMounts"], "keys")
			if keysMount == nil || keysMount["mountPath"] != "/app/keys" || keysMount["readOnly"] != true {
				t.Errorf("server keys mount = %v, want /app/keys readOnly", keysMount)
			}
			if namedItem(server["volumeMounts"], "keys-secret") != nil {
				t.Error("the server container must not mount the Secret itself (root-owned files fail the key permission check)")
			}

			keys := namedItem(spec["volumes"], "keys")
			if nested(keys, "emptyDir", "medium") != "Memory" || keys["persistentVolumeClaim"] != nil {
				t.Errorf("keys volume = %v, want a memory emptyDir", keys)
			}
			sec := namedItem(spec["volumes"], "keys-secret")
			if nested(sec, "secret", "secretName") != "keyorix-keys-1" {
				t.Errorf("keys-secret volume = %v, want Secret keyorix-keys-1", sec)
			}
			if mode, _ := nested(sec, "secret", "defaultMode").(int); mode != 0o440 {
				t.Errorf("keys-secret defaultMode = %v, want 0440", nested(sec, "secret", "defaultMode"))
			}

			prep := namedItem(spec["initContainers"], "prepare-keys")
			if prep == nil {
				t.Fatal("no prepare-keys init container")
			}
			cmd, _ := prep["command"].([]any)
			script, _ := cmd[len(cmd)-1].(string)
			for _, want := range []string{"set -eu", "umask 077",
				"cp /mnt/keys-secret/data.key /app/keys/data.key",
				"cp /mnt/keys-secret/kek.salt /app/keys/kek.salt",
				"keyset.manifest.json", "chmod 600"} {
				if !strings.Contains(script, want) {
					t.Errorf("prepare-keys script lacks %q:\n%s", want, script)
				}
			}
			for _, banned := range []string{"cat ", "echo", "ls", "set -x", "base64"} {
				if strings.Contains(script, banned) {
					t.Errorf("prepare-keys script contains %q: it must print nothing about the key files", banned)
				}
			}
			if m := namedItem(prep["volumeMounts"], "keys-secret"); m == nil || m["readOnly"] != true {
				t.Errorf("prepare-keys must mount the Secret read-only: %v", m)
			}

			cfg := serverConfigYAML(t, docs)
			if got := nested(cfg, "storage", "encryption", "key_dir_lock"); got != "database" {
				t.Errorf("key_dir_lock = %v, want database", got)
			}
			if got := nested(cfg, "storage", "type"); got != "postgres" {
				t.Errorf("storage.type = %v: key_dir_lock: database is PostgreSQL only", got)
			}
			if got := nested(cfg, "storage", "encryption", "dek_path"); got != "/app/keys/data.key" {
				t.Errorf("dek_path = %v", got)
			}
			if got := nested(cfg, "storage", "encryption", "salt_path"); got != "/app/keys/kek.salt" {
				t.Errorf("salt_path = %v", got)
			}
		})
	}
}

// Every render with more than one replica carries key_dir_lock: database and
// PostgreSQL: the condition the server's multi-replica safety rests on. Checked
// over the shapes that render at all (the rest are refused below).
func TestHelmKeysSecret_EveryMultiReplicaRenderIsDatabaseLockedPostgres(t *testing.T) {
	requireHelm(t)
	for _, sets := range [][]string{
		append(keysSecretSets, "server.replicas=2"),
		append(keysSecretSets, "server.replicas=5", "postgresql.enabled=true", "postgresql.auth.password=x"),
		append(keysSecretSets, "server.replicas=2", "externalDatabase.pooler=pgbouncer-transaction"),
	} {
		cfg := serverConfigYAML(t, haDocs(t, sets...))
		if nested(cfg, "storage", "encryption", "key_dir_lock") != "database" || nested(cfg, "storage", "type") != "postgres" {
			t.Errorf("%v: key_dir_lock=%v storage.type=%v, want database/postgres", sets,
				nested(cfg, "storage", "encryption", "key_dir_lock"), nested(cfg, "storage", "type"))
		}
	}
}

// One replica without the opt-in keeps today's behaviour: the keys PVC, mounted
// writable, no init container, no key_dir_lock.
func TestHelmKeysSecret_DefaultSingleReplicaKeepsThePVC(t *testing.T) {
	requireHelm(t)
	docs := haDocs(t)
	var pvc map[string]any
	for _, d := range docs {
		if d["kind"] == "PersistentVolumeClaim" {
			pvc = d
		}
	}
	if pvc == nil || nested(pvc, "metadata", "name") != "kx-keyorix-server-keys" {
		t.Fatalf("default render has no keys PVC: %v", pvc)
	}
	spec := podSpec(t, docs)
	if nested(namedItem(spec["volumes"], "keys"), "persistentVolumeClaim", "claimName") != "kx-keyorix-server-keys" {
		t.Error("default keys volume is not the PVC")
	}
	if namedItem(spec["volumes"], "keys-secret") != nil || namedItem(spec["initContainers"], "prepare-keys") != nil {
		t.Error("default render must not use a key Secret")
	}
	if m := namedItem(namedItem(spec["containers"], "server")["volumeMounts"], "keys"); m["readOnly"] == true {
		t.Error("the default keys mount must stay writable (first boot generates the keys)")
	}
	if got := nested(serverConfigYAML(t, docs), "storage", "encryption", "key_dir_lock"); got != nil {
		t.Errorf("default key_dir_lock = %v, want unset (flock)", got)
	}
}

// Every Secret-mode shape that cannot work is refused at render time.
func TestHelmKeysSecret_RefusesUnsafeCombinations(t *testing.T) {
	requireHelm(t)
	for _, tc := range []struct {
		name string
		sets []string
		want string
	}{
		{"Secret mode without a name", []string{"server.keysSecret.enabled=true", "server.keysPersistence.enabled=false"}, "needs server.keysSecret.name"},
		{"Secret mode next to the keys PVC", []string{"server.keysSecret.enabled=true", "server.keysSecret.name=k"}, "set server.keysPersistence.enabled=false"},
		{"Secret mode with an RWX PVC and replicas", []string{"server.replicas=2", "server.keysSecret.enabled=true", "server.keysSecret.name=k", "server.keysPersistence.accessMode=ReadWriteMany"}, "ReadWriteMany keys volume"},
		{"invalid Secret name (schema)", append([]string{"server.keysSecret.name=Keys_1"}, keysSecretSets[0], keysSecretSets[2]), "does not match pattern"},
		{"unknown keysSecret field (schema)", append([]string{"server.keysSecret.nmae=k"}, keysSecretSets...), "additional properties"},
		{"replicas without Secret mode", []string{"server.replicas=2"}, "needs Secret mode"},
		{"replicas with Secret mode disabled", []string{"server.replicas=2", "server.keysSecret.enabled=false", "server.keysSecret.name=k", "server.keysPersistence.enabled=false"}, "needs Secret mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := haRender(t, tc.sets...)
			if err == nil {
				t.Fatalf("render succeeded, want a refusal mentioning %q", tc.want)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("refusal does not mention %q:\n%s", tc.want, out)
			}
		})
	}
}
