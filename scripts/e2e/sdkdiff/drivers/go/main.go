// Command driver executes one SDK-level operation per stdin line against the
// Keyorix Go SDK and prints one JSON line per request. See ../../PROTOCOL.md.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	keyorix "github.com/keyorixhq/keyorix-sdks/go"
)

var plant = os.Getenv("SDKDIFF_PLANT")

func main() {
	r := bufio.NewReaderSize(os.Stdin, 1<<20)
	w := bufio.NewWriterSize(os.Stdout, 1<<16)
	for {
		line, err := r.ReadString('\n')
		if line != "" {
			out := handle(strings.Split(strings.TrimRight(line, "\r\n"), "\t"))
			b, _ := json.Marshal(out)
			_, _ = w.Write(append(b, '\n'))
			_ = w.Flush()
		}
		if err != nil {
			return
		}
	}
}

// field decodes one protocol field: "~" is null, anything else is hex(UTF-8).
func field(f string) *string {
	if f == "~" {
		return nil
	}
	b, err := hex.DecodeString(f)
	if err != nil {
		s := "�bad-hex"
		return &s
	}
	s := string(b)
	return &s
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func handle(f []string) map[string]any {
	if len(f) < 4 {
		return map[string]any{"driver_error": "short line"}
	}
	cmd := f[0]
	base := str(field(f[1]))
	token := str(field(f[2]))
	timeoutMs, _ := strconv.Atoi(f[3])
	args := make([]*string, 0, len(f)-4)
	for _, a := range f[4:] {
		args = append(args, field(a))
	}
	arg := func(i int) *string {
		if i < len(args) {
			return args[i]
		}
		return nil
	}

	var opts []keyorix.Option
	if timeoutMs > 0 {
		opts = append(opts, keyorix.WithTimeout(time.Duration(timeoutMs)*time.Millisecond))
	}
	ctx := context.Background()
	start := time.Now()
	res := func() map[string]any {
		if cmd == "construct" {
			if _, err := keyorix.New(base, "x"); err != nil {
				return fail(err, "validation")
			}
			return map[string]any{"ok": true, "value": map[string]any{"accepted": true}}
		}
		if cmd == "login" {
			lctx := ctx
			if timeoutMs > 0 {
				var cancel context.CancelFunc
				lctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
				defer cancel()
			}
			tok, err := keyorix.Login(lctx, base, str(arg(0)), str(arg(1)))
			if err != nil {
				return fail(err, "")
			}
			return map[string]any{"ok": true, "value": map[string]any{"token_len": len(tok)}}
		}
		c, err := keyorix.New(base, token, opts...)
		if err != nil {
			return fail(err, "validation")
		}
		switch cmd {
		case "health":
			if err := c.Health(ctx); err != nil {
				return fail(err, "")
			}
			return map[string]any{"ok": true, "value": true}
		case "list_secrets":
			s, err := c.ListSecretsScoped(ctx, keyorix.ProjectByName("alpha"), keyorix.EnvironmentByName(str(arg(0))))
			if err != nil {
				return fail(err, "")
			}
			return map[string]any{"ok": true, "value": secretList(s)}
		case "get_secret":
			v, err := c.GetSecretScoped(ctx, str(arg(0)), keyorix.ProjectByName("alpha"), keyorix.EnvironmentByName(str(arg(1))))
			if err != nil {
				return fail(err, "")
			}
			return map[string]any{"ok": true, "value": v}
		case "get_secret_in":
			v, err := c.GetSecretIn(ctx, str(arg(0)), str(arg(1)), str(arg(2)))
			if err != nil {
				return fail(err, "")
			}
			return map[string]any{"ok": true, "value": v}
		case "get_secret_by_ref":
			v, err := c.GetSecretByRef(ctx, str(arg(0)))
			if err != nil {
				return fail(err, "")
			}
			return map[string]any{"ok": true, "value": v}
		case "list_deleted_secrets":
			id, perr := strconv.ParseUint(str(arg(0)), 10, 32)
			if perr != nil || len(str(arg(0))) > 9 {
				return map[string]any{"na": true}
			}
			s, err := c.ListDeletedSecrets(ctx, keyorix.ProjectByID(uint(id)))
			if err != nil {
				return fail(err, "")
			}
			return map[string]any{"ok": true, "value": secretList(s)}
		case "list_projects":
			p, err := c.ListProjects(ctx)
			if err != nil {
				return fail(err, "")
			}
			out := make([]any, 0, len(p))
			for _, x := range p {
				out = append(out, projectMap(x))
			}
			return map[string]any{"ok": true, "value": out}
		case "create_project":
			p, err := c.CreateProject(ctx, str(arg(0)), str(arg(1)))
			if err != nil {
				return fail(err, "")
			}
			return map[string]any{"ok": true, "value": projectMap(*p)}
		case "list_environments":
			id, perr := strconv.ParseUint(str(arg(0)), 10, 64)
			if perr != nil || id > uint64(^uint(0)) {
				return map[string]any{"inexpressible": true}
			}
			e, err := c.ListEnvironments(ctx, uint(id))
			if err != nil {
				return fail(err, "")
			}
			out := make([]any, 0, len(e))
			for _, x := range e {
				out = append(out, map[string]any{"id": x.ID, "project_id": x.ProjectID, "name": x.Name})
			}
			return map[string]any{"ok": true, "value": out}
		}
		return map[string]any{"driver_error": "unknown cmd " + cmd}
	}()
	res["ms"] = time.Since(start).Milliseconds()
	return res
}

func projectMap(x keyorix.Project) map[string]any {
	return map[string]any{"id": x.ID, "name": x.Name, "description": x.Description, "created_at": ts(x.CreatedAt)}
}

func ts(t time.Time) any {
	if t.IsZero() {
		return "0001-01-01T00:00:00Z"
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// fail maps a native Go SDK error to the pre-registered class by native type.
// force overrides the mapping (used for constructor failures: "validation").
func fail(err error, force string) map[string]any {
	class := "other"
	var status any
	var ae *keyorix.APIError
	var au *keyorix.AuthError
	var snf *keyorix.SecretNotFoundError
	var ue *url.Error
	var se *json.SyntaxError
	var te *json.UnmarshalTypeError
	switch {
	case force != "":
		class = force
	case errors.As(err, &au):
		class, status = "auth", au.StatusCode
	case errors.As(err, &snf):
		class = "not_found"
	case errors.As(err, &ae):
		class, status = "http", ae.StatusCode
		if plant == "P3" && ae.StatusCode == 404 {
			class = "auth"
		}
	case errors.As(err, &ue):
		class = "network"
		if ue.Timeout() {
			class = "timeout"
		}
	case errors.As(err, &se), errors.As(err, &te), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		class = "decode"
	}
	return map[string]any{"ok": false, "class": class, "status": status, "native": fmt.Sprintf("%T", err), "msg": err.Error(),
		"sdk_error": strings.HasPrefix(err.Error(), "keyorix:") || strings.Contains(fmt.Sprintf("%T", err), "keyorix."), "full": fullErr(err)}
}

func secretList(s []keyorix.Secret) []any {
	out := make([]any, 0, len(s))
	for _, x := range s {
		out = append(out, map[string]any{"id": x.ID, "name": x.Name, "type": x.Type, "project_id": x.ProjectID,
			"environment": x.Environment, "created_at": ts(x.CreatedAt), "purge_at": tsp(x.PurgeAt)})
	}
	return out
}

func tsp(t *time.Time) any {
	if t == nil {
		return ""
	}
	return ts(*t)
}

// fullErr renders the whole error chain the way a logger would (%+v per link).
func fullErr(err error) string {
	var b strings.Builder
	for i := 0; err != nil && i < 20; i++ {
		fmt.Fprintf(&b, "%T: %+v | ", err, err)
		err = errors.Unwrap(err)
	}
	return b.String()
}
