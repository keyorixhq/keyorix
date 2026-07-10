package project

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupEmbedded points the project commands at an isolated temp config in local
// (embedded SQLite) mode, so common.NewRemoteClient returns false and the commands
// take their embedded path against a throwaway database. Also resets the package-level
// command flag vars after the test so cases don't leak into each other.
func setupEmbedded(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, config.Save(cfgPath, &config.Config{
		Locale:  config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
		Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: filepath.Join(dir, "test.db")}},
	}))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)
	t.Setenv("XDG_CONFIG_HOME", dir) // isolate cli.yaml: embedded, no active project
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_PROJECT", "")
	require.NoError(t, i18n.InitializeForTesting())

	t.Cleanup(func() {
		createName, createDescription, createEnvs = "", "", ""
		envProjectFlag, envCreateName = "", ""
	})
}

func embeddedCore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	return svc
}

func TestRunCreate_Embedded(t *testing.T) {
	setupEmbedded(t)
	createName = "web"
	createEnvs = "dev,prod"

	out := captureStdout(t, func() { require.NoError(t, runCreate(nil, nil)) })
	assert.Contains(t, out, "Project created: id=")
	assert.Contains(t, out, "Environments seeded: dev,prod")

	svc := embeddedCore(t)
	projects, err := svc.ListProjects(context.Background())
	require.NoError(t, err)
	require.Len(t, projects, 1)
	assert.Equal(t, "web", projects[0].Name)

	envs, err := svc.ListEnvironmentsByProject(context.Background(), projects[0].ID)
	require.NoError(t, err)
	var names []string
	for _, e := range envs {
		names = append(names, e.Name)
	}
	assert.ElementsMatch(t, []string{"dev", "prod"}, names)
}

func TestRunCreate_RequiresName(t *testing.T) {
	setupEmbedded(t)
	createName = ""
	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--name is required")
}

func TestRunCreate_RejectsEmptyEnvs(t *testing.T) {
	setupEmbedded(t)
	createName = "x"
	createEnvs = " , , "
	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--envs must not be empty")
}

func TestRunList_Embedded(t *testing.T) {
	setupEmbedded(t)

	out := captureStdout(t, func() { require.NoError(t, runList(nil, nil)) })
	assert.Contains(t, out, "No projects found.")

	_, err := embeddedCore(t).CreateProject(context.Background(), "alpha", "first project")
	require.NoError(t, err)

	out = captureStdout(t, func() { require.NoError(t, runList(nil, nil)) })
	assert.Contains(t, out, "alpha")
	assert.Contains(t, out, "first project")
}

func TestRunEnvironments_Embedded(t *testing.T) {
	setupEmbedded(t)
	p, err := embeddedCore(t).CreateProjectWithEnvs(context.Background(), "web", "", []string{"dev"})
	require.NoError(t, err)

	out := captureStdout(t, func() {
		require.NoError(t, runEnvironments(nil, []string{strconv.Itoa(int(p.ID))}))
	})
	assert.Contains(t, out, "dev")

	err = runEnvironments(nil, []string{"not-a-number"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid project ID")
}

func TestRunEnv_CreateListDelete_Embedded(t *testing.T) {
	setupEmbedded(t)
	ctx := context.Background()
	_, err := embeddedCore(t).CreateProject(ctx, "web", "")
	require.NoError(t, err)
	envProjectFlag = "web"

	// create
	envCreateName = "qa"
	out := captureStdout(t, func() { require.NoError(t, runEnvCreate(nil, nil)) })
	assert.Contains(t, out, `Environment "qa" created`)

	// list shows it
	out = captureStdout(t, func() { require.NoError(t, runEnvList(nil, nil)) })
	assert.Contains(t, out, "qa")

	// delete it (resolve its id first)
	svc := embeddedCore(t)
	projects, err := svc.ListProjects(ctx)
	require.NoError(t, err)
	envs, err := svc.ListEnvironmentsByProject(ctx, projects[0].ID)
	require.NoError(t, err)
	var qaID uint
	for _, e := range envs {
		if e.Name == "qa" {
			qaID = e.ID
		}
	}
	require.NotZero(t, qaID)

	out = captureStdout(t, func() {
		require.NoError(t, runEnvDelete(nil, []string{strconv.Itoa(int(qaID))}))
	})
	assert.Contains(t, out, "deleted")

	err = runEnvDelete(nil, []string{"bad"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid environment ID")
}

func TestResolveProjectContext_NoProject(t *testing.T) {
	setupEmbedded(t)
	// No --project flag, no KEYORIX_PROJECT, no active cli.yaml project.
	_, _, err := resolveProjectContext("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no project specified")
}

func TestRunUse_And_Current_Embedded(t *testing.T) {
	setupEmbedded(t)
	_, err := embeddedCore(t).CreateProject(context.Background(), "web", "")
	require.NoError(t, err)

	out := captureStdout(t, func() { require.NoError(t, runCurrent(nil, nil)) })
	assert.Contains(t, out, "No active project set.")

	out = captureStdout(t, func() { require.NoError(t, runUse(nil, []string{"web"})) })
	assert.Contains(t, out, `Active project set to "web"`)

	out = captureStdout(t, func() { require.NoError(t, runCurrent(nil, nil)) })
	assert.Contains(t, out, "web")

	err = runUse(nil, []string{"ghost"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRunCurrent_FromEnvVar(t *testing.T) {
	setupEmbedded(t)
	t.Setenv("KEYORIX_PROJECT", "envproj")
	out := captureStdout(t, func() { require.NoError(t, runCurrent(nil, nil)) })
	assert.Contains(t, out, "envproj (from KEYORIX_PROJECT)")
}

func TestRunDescribe_Embedded(t *testing.T) {
	setupEmbedded(t)
	_, err := embeddedCore(t).CreateProjectWithEnvs(context.Background(), "web", "the web project", []string{"dev", "prod"})
	require.NoError(t, err)

	out := captureStdout(t, func() { require.NoError(t, runDescribe(nil, []string{"web"})) })
	assert.Contains(t, out, "Project:      web")
	assert.Contains(t, out, "the web project")
	assert.Contains(t, out, "dev")
	assert.Contains(t, out, "Secrets:")

	err = runDescribe(nil, []string{"ghost"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
