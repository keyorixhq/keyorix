package configspace

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestMatrix runs the whole campaign. It is skipped unless CONFIGSPACE_RUN=1, writes
// details only into CONFIGSPACE_OUT (keep that directory private), and logs counts.
//
//	CONFIGSPACE_RUN=1 CONFIGSPACE_BIN=/path/keyorix-server CONFIGSPACE_OUT=/private/out \
//	  CONFIGSPACE_STAGES=inproc,proc go test ./scripts/fuzzing/configspace -run TestMatrix -v -timeout 3h
func TestMatrix(t *testing.T) {
	if os.Getenv("CONFIGSPACE_RUN") != "1" {
		t.Skip("set CONFIGSPACE_RUN=1 to run the config-space campaign")
	}
	bin := os.Getenv("CONFIGSPACE_BIN")
	out := os.Getenv("CONFIGSPACE_OUT")
	if out == "" {
		t.Fatal("CONFIGSPACE_OUT must name a private directory")
	}
	work := os.Getenv("CONFIGSPACE_WORK")
	if work == "" {
		work = t.TempDir()
	}
	tplDir := os.Getenv("CONFIGSPACE_TEMPLATE")
	if tplDir == "" {
		tplDir = filepath.Join(work, "template")
		if bin == "" {
			t.Fatal("CONFIGSPACE_BIN or CONFIGSPACE_TEMPLATE is required")
		}
		if err := BuildTemplate(bin, tplDir); err != nil {
			t.Fatal(err)
		}
	}
	tpl, err := LoadTemplate(tplDir)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("CONFIGSPACE_STAGES") == "inproc" {
		bin = ""
	}
	o := RunOptions{
		Model: mustModel(t), Template: tpl, Work: filepath.Join(work, "cases"), Out: out, Bin: bin,
		Mutations: envInt("CONFIGSPACE_MUTATIONS", 400), ProcMutants: envInt("CONFIGSPACE_PROC_MUTANTS", 30),
		ProcInvalid: envInt("CONFIGSPACE_PROC_INVALID", 60), Seed: int64(envInt("CONFIGSPACE_SEED", 20261107)),
		Log: t.Logf,
	}
	sum, err := Run(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("summary: %+v", sum)
}

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return def
}
