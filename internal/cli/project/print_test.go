package project

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStdout redirects os.Stdout for the duration of fn and returns everything
// written to it — the print* helpers all write to stdout via fmt.Printf.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()
	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func TestSplitEnvNames(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"simple", "dev,staging,prod", []string{"dev", "staging", "prod"}},
		{"trims whitespace", " dev , staging ,prod ", []string{"dev", "staging", "prod"}},
		{"drops empty segments", "dev,,prod,", []string{"dev", "prod"}},
		{"all empty/whitespace yields none", " , , ", []string{}},
		{"single", "dev", []string{"dev"}},
		{"empty string yields none", "", []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitEnvNames(tt.in)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPrintProjects(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		out := captureStdout(t, func() { printProjects(nil) })
		assert.Equal(t, "No projects found.\n", out)
	})

	t.Run("lists rows with header", func(t *testing.T) {
		out := captureStdout(t, func() {
			printProjects([]*models.Project{
				{ID: 1, Name: "web", Description: "frontend"},
				{ID: 2, Name: "api", Description: ""},
			})
		})
		assert.Contains(t, out, "ID")
		assert.Contains(t, out, "NAME")
		assert.Contains(t, out, "web")
		assert.Contains(t, out, "frontend")
		assert.Contains(t, out, "api")
	})

	t.Run("truncates a long description", func(t *testing.T) {
		long := strings.Repeat("x", 50)
		out := captureStdout(t, func() {
			printProjects([]*models.Project{{ID: 1, Name: "p", Description: long}})
		})
		assert.Contains(t, out, strings.Repeat("x", 37)+"...")
		assert.NotContains(t, out, strings.Repeat("x", 41))
	})
}

func TestPrintProjectDetails(t *testing.T) {
	t.Run("with description and envs", func(t *testing.T) {
		out := captureStdout(t, func() {
			printProjectDetails("web", "the frontend", 7, []*models.Environment{
				{ID: 1, Name: "dev"}, {ID: 2, Name: "prod"},
			})
		})
		assert.Contains(t, out, "Project:      web (id=7)")
		assert.Contains(t, out, "Description:  the frontend")
		assert.Contains(t, out, "Environments: 2")
		assert.Contains(t, out, "- dev (id=1)")
		assert.Contains(t, out, "- prod (id=2)")
	})

	t.Run("omits the description line when empty", func(t *testing.T) {
		out := captureStdout(t, func() {
			printProjectDetails("web", "", 7, nil)
		})
		assert.NotContains(t, out, "Description:")
		assert.Contains(t, out, "Environments: 0")
	})
}

func TestPrintEnvironments(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		out := captureStdout(t, func() { printEnvironments(nil, 3) })
		assert.Equal(t, "No environments found for project 3.\n", out)
	})
	t.Run("populated", func(t *testing.T) {
		out := captureStdout(t, func() {
			printEnvironments([]*models.Environment{{ID: 5, Name: "dev"}}, 3)
		})
		assert.Contains(t, out, "Environments for project 3:")
		assert.Contains(t, out, "dev")
	})
}

func TestPrintEnvironmentTable(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		out := captureStdout(t, func() { printEnvironmentTable(nil, "web") })
		assert.Equal(t, "No environments found for project \"web\".\n", out)
	})
	t.Run("populated", func(t *testing.T) {
		out := captureStdout(t, func() {
			printEnvironmentTable([]*models.Environment{{ID: 5, Name: "prod"}}, "web")
		})
		assert.Contains(t, out, `Environments for project "web":`)
		assert.Contains(t, out, "prod")
	})
}

func TestPrintCreateResult(t *testing.T) {
	t.Run("with explicit envs flag", func(t *testing.T) {
		out := captureStdout(t, func() { printCreateResult(9, "web", "dev,prod") })
		assert.Contains(t, out, `Project created: id=9 name="web"`)
		assert.Contains(t, out, "Environments seeded: dev,prod")
	})
	t.Run("defaults when no envs flag", func(t *testing.T) {
		out := captureStdout(t, func() { printCreateResult(9, "web", "") })
		assert.Contains(t, out, "Default environments (development, staging, production)")
	})
}
