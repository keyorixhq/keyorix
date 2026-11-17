package main

// Valid response templates of the hostile-server mode. The shapes are those of the throwaway keyorix-server the
// differential harness boots (captured once; synthetic data only), trimmed to the fields the SDKs read plus a few
// neighbours that make key scans non-trivial. {{MAIN}} is the main string field of the class, {{ID}} the id of the
// first (used) list item.

import (
	"strconv"
	"strings"
)

// Env is what a mutation sees of the request it answers.
type Env struct {
	Cls        string
	Method     string
	URI        string
	Path       string
	Page       int
	AcceptGzip bool
	Hdr        map[string][]string
}

type tmpl struct {
	status int
	text   string
	main   string // default main string
	id     string // default id
	key    string // JSON key of the main string field
	list   string // key of the list inside data ("" if none)
}

const secObj = `{"id":%ID%,"project_id":2,"environment_id":6,"name":"%NAME%","is_secret":true,"type":"password","read_count":0,"status":"active","created_by":"synthetic","owner_id":1,"created_at":"2026-11-07T15:59:43.142596Z","updated_at":"2026-11-07T15:59:43.142596Z","auto_rotate":false,"project_name":"alpha","environment_name":"production","is_shared":false,"is_owned_by_user":true,"share_count":0,"sharing_indicators":{"icon":"owned","badge":"OWNER","status_text":"You own this secret","can_read":true,"can_write":true,"can_share":true,"can_delete":true}}`

func secItem(id, name string) string {
	return strings.NewReplacer("%ID%", id, "%NAME%", name).Replace(secObj)
}

var templates = map[string]tmpl{
	"H": {200, `{"auth_rate_limit":"ok","status":"{{MAIN}}","timestamp":"2026-11-07T21:50:18.563303Z","uptime":"537.801875ms"}`, "healthy", "", "status", ""},
	"A": {200, `{"data":{"token":"{{MAIN}}","expires_at":"2026-11-08T21:50:19Z","user_id":1,"username":"synthetic","role":"admin","roles":["admin"],"permissions":["secrets.read","secrets.write"],"account_state":"active"},"message":"Login successful","success":true}`, "SYNTHETIC-SESSION-TOKEN-0001", "", "token", ""},
	"P": {200, `{"data":{"projects":[{"id":{{ID}},"name":"{{MAIN}}","description":"synthetic alpha","secret_count":3,"environment_count":3,"last_activity":"2026-11-07T15:59:43.178694Z","deleted":false},{"id":1,"name":"default","description":"Default project","secret_count":0,"environment_count":3,"last_activity":"2026-11-07T15:59:42.934407Z","deleted":false}]},"success":true}`, "alpha", "2", "name", "projects"},
	"C": {201, `{"data":{"id":{{ID}},"name":"{{MAIN}}","description":"d","require_mfa":false,"created_at":"2026-11-07T21:50:19.49343Z","updated_at":"2026-11-07T21:50:19.49343Z"},"message":"Project created","success":true}`, "cap1", "5", "name", ""},
	"E": {200, `{"data":{"environments":[{"id":{{ID}},"project_id":2,"name":"{{MAIN}}","secret_count":3,"created_at":"2026-11-07T15:59:43.138777Z","updated_at":"2026-11-07T15:59:43.138777Z"},{"id":4,"project_id":2,"name":"development","secret_count":0,"created_at":"2026-11-07T15:59:43.138712Z","updated_at":"2026-11-07T15:59:43.138712Z"},{"id":5,"project_id":2,"name":"staging","secret_count":0,"created_at":"2026-11-07T15:59:43.138752Z","updated_at":"2026-11-07T15:59:43.138752Z"}]},"success":true}`, "production", "6", "name", "environments"},
	"L": {200, `{"success":true,"data":{"secrets":[` + secItem("{{ID}}", "{{MAIN}}") + `,` + secItem("2", "api key") + `,` + secItem("3", "val-json") + `],"total":3,"page":{{PAGE}},"page_size":100,"total_pages":{{PAGES}},"owned_count":3,"shared_count":0,"acl_granted_count":0}}`, "db-password", "1", "name", "secrets"},
	"V": {200, `{"success":true,"data":{"secret":{"id":1,"project_id":2,"environment_id":6,"name":"db-password","is_secret":true,"type":"password","read_count":0,"status":"active","created_by":"synthetic","owner_id":1,"is_shared":false,"created_at":"2026-11-07T15:59:43.142596Z","updated_at":"2026-11-07T15:59:43.142596Z","auto_rotate":false},"value":"{{MAIN}}"}}`, "s3cret-value", "", "value", ""},
	"D": {200, `{"success":true,"data":{"deleted":[{"id":{{ID}},"project_id":2,"name":"{{MAIN}}","type":"password","deleted_at":"2026-11-01T00:00:00Z","purge_at":"2026-12-01T00:00:00Z"}],"total":1}}`, "old-key", "9", "name", "deleted"},
}

// renderT renders a class template with explicit main/id/pages.
func renderT(cls, mainS, id, pages string, page int) []byte {
	t, ok := templates[cls]
	if !ok {
		return []byte(`{"code":404,"error":"NotFound","message":"Resource not found"}`)
	}
	if page < 1 {
		page = 1
	}
	return []byte(strings.NewReplacer("{{MAIN}}", mainS, "{{ID}}", id, "{{PAGES}}", pages, "{{PAGE}}", strconv.Itoa(page)).Replace(t.text))
}

// validDoc is the unmutated body of a class.
func validDoc(cls string, page int) []byte {
	t := templates[cls]
	return renderT(cls, t.main, t.id, "1", page)
}

func validPlanFor(e *Env) *Plan {
	t, ok := templates[e.Cls]
	if !ok {
		p := validPlan(404, []byte(`{"code":404,"error":"NotFound","message":"Resource not found"}`))
		return p
	}
	return validPlan(t.status, validDoc(e.Cls, e.Page))
}
