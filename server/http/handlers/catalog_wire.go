// catalog_wire.go — snake_case wire types for internal/storage/models.Project and
// Environment (both carry zero json tags — every human-facing catalog route
// returning either raw was mixed-casing against openapi.yaml, which already
// documented snake_case). See docs/findings/2026-09-25-FINDING-api-raw-model-exposure.md.
//
// Same field shape as project_catalog_proxy.go's projectProxyWire and
// environment_catalog_proxy.go's environmentProxyWire (the /system RemoteStorage-proxy
// tier's own wire types for these two models) — kept in sync deliberately so the
// human-facing and proxy surfaces never mixed-case relative to each other. Not merged
// into one shared type: those two files are CLI-RELEASE-owned (Phase 6 /system proxy
// tier), so promoting them fully is left as a follow-up for that track.
package handlers

import (
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type projectWire struct {
	ID          uint       `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	RequireMFA  bool       `json:"require_mfa"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
}

func newProjectWire(p *models.Project) projectWire {
	w := projectWire{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		RequireMFA:  p.RequireMFA,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
	if p.DeletedAt.Valid {
		t := p.DeletedAt.Time
		w.DeletedAt = &t
	}
	return w
}

type environmentWire struct {
	ID        uint       `json:"id"`
	ProjectID uint       `json:"project_id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

func newEnvironmentWire(e *models.Environment) environmentWire {
	w := environmentWire{
		ID:        e.ID,
		ProjectID: e.ProjectID,
		Name:      e.Name,
		CreatedAt: e.CreatedAt,
		UpdatedAt: e.UpdatedAt,
	}
	if e.DeletedAt.Valid {
		t := e.DeletedAt.Time
		w.DeletedAt = &t
	}
	return w
}

func newEnvironmentWireList(envs []*models.Environment) []environmentWire {
	out := make([]environmentWire, 0, len(envs))
	for _, e := range envs {
		out = append(out, newEnvironmentWire(e))
	}
	return out
}

type envCloneResultWire struct {
	SourceEnv      string   `json:"source_env"`
	DestEnv        string   `json:"dest_env"`
	SecretsCloned  int      `json:"secrets_cloned"`
	SecretsSkipped int      `json:"secrets_skipped"`
	Errors         []string `json:"errors,omitempty"`
}

func newEnvCloneResultWire(r *core.EnvCloneResult) envCloneResultWire {
	return envCloneResultWire{
		SourceEnv:      r.SourceEnv,
		DestEnv:        r.DestEnv,
		SecretsCloned:  r.SecretsCloned,
		SecretsSkipped: r.SecretsSkipped,
		Errors:         r.Errors,
	}
}
