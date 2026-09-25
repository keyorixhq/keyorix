// catalog_wire.go — snake_case wire types for internal/storage/models.Project
// and models.Environment (0 fields tagged on either) and internal/core.EnvCloneResult
// (also untagged). Mirrors environment_catalog_proxy.go's environmentProxyWire shape —
// that type stays where it is (the proxy tier is being deleted in PR 14; this file's
// types are independent, for the human-facing /api/v1/projects and /api/v1/environments
// routes only). See docs/findings/2026-09-25-FINDING-api-raw-model-exposure.md.
package handlers

import (
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type projectWire struct {
	ID          uint       `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
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
