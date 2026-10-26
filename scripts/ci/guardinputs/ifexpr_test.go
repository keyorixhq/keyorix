package main

import (
	"fmt"
	"strings"
	"testing"
)

// evalIf evaluates the subset of the GitHub Actions expression language that
// ci.yml's job `if:` conditions use: string literals, context paths, == / !=,
// !, &&, ||, parentheses, always() and contains(a, b). resolve maps a context
// path (github.event_name, needs.changes.outputs.docs_only, ...) to its value;
// it returns an error for a path it does not model, so a condition that starts
// depending on something new fails the test instead of evaluating silently.
func evalIf(expr string, resolve func(string) (string, error)) (bool, error) {
	expr = strings.TrimSpace(expr)
	expr = strings.TrimSuffix(strings.TrimPrefix(expr, "${{"), "}}")
	p := &ifParser{toks: tokenize(expr), resolve: resolve}
	v, err := p.or()
	if err != nil {
		return false, err
	}
	if p.pos != len(p.toks) {
		return false, fmt.Errorf("trailing tokens at %q in %q", p.toks[p.pos], expr)
	}
	return truthy(v), nil
}

type ifVal struct {
	s    string
	b    bool
	isB  bool
	list bool // the labels list: contains() over it is false (no label set)
}

func truthy(v ifVal) bool {
	if v.isB {
		return v.b
	}
	return v.s != ""
}

func (v ifVal) str() string {
	if v.isB {
		if v.b {
			return "true"
		}
		return "false"
	}
	return v.s
}

func tokenize(s string) []string {
	var toks []string
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '\'':
			j := i + 1
			var b strings.Builder
			for j < len(s) {
				if s[j] == '\'' {
					if j+1 < len(s) && s[j+1] == '\'' {
						b.WriteByte('\'')
						j += 2
						continue
					}
					break
				}
				b.WriteByte(s[j])
				j++
			}
			toks = append(toks, "'"+b.String())
			i = j + 1
		case strings.HasPrefix(s[i:], "==") || strings.HasPrefix(s[i:], "!=") ||
			strings.HasPrefix(s[i:], "&&") || strings.HasPrefix(s[i:], "||"):
			toks = append(toks, s[i:i+2])
			i += 2
		case c == '!' || c == '(' || c == ')' || c == ',':
			toks = append(toks, string(c))
			i++
		default:
			j := i
			for j < len(s) && strings.IndexByte(" \t\n\r'=!&|(),", s[j]) < 0 {
				j++
			}
			if j == i {
				j = i + 1
			}
			toks = append(toks, s[i:j])
			i = j
		}
	}
	return toks
}

type ifParser struct {
	toks    []string
	pos     int
	resolve func(string) (string, error)
}

func (p *ifParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *ifParser) next() string { t := p.peek(); p.pos++; return t }

func (p *ifParser) or() (ifVal, error) {
	l, err := p.and()
	if err != nil {
		return l, err
	}
	for p.peek() == "||" {
		p.next()
		r, err := p.and()
		if err != nil {
			return r, err
		}
		l = ifVal{b: truthy(l) || truthy(r), isB: true}
	}
	return l, nil
}

func (p *ifParser) and() (ifVal, error) {
	l, err := p.cmp()
	if err != nil {
		return l, err
	}
	for p.peek() == "&&" {
		p.next()
		r, err := p.cmp()
		if err != nil {
			return r, err
		}
		l = ifVal{b: truthy(l) && truthy(r), isB: true}
	}
	return l, nil
}

func (p *ifParser) cmp() (ifVal, error) {
	l, err := p.unary()
	if err != nil {
		return l, err
	}
	if op := p.peek(); op == "==" || op == "!=" {
		p.next()
		r, err := p.unary()
		if err != nil {
			return r, err
		}
		eq := strings.EqualFold(l.str(), r.str())
		if op == "!=" {
			eq = !eq
		}
		return ifVal{b: eq, isB: true}, nil
	}
	return l, nil
}

func (p *ifParser) unary() (ifVal, error) {
	if p.peek() == "!" {
		p.next()
		v, err := p.unary()
		return ifVal{b: !truthy(v), isB: true}, err
	}
	return p.primary()
}

func (p *ifParser) primary() (ifVal, error) {
	t := p.next()
	switch {
	case t == "":
		return ifVal{}, fmt.Errorf("unexpected end of expression")
	case t == "(":
		v, err := p.or()
		if err != nil {
			return v, err
		}
		if p.next() != ")" {
			return v, fmt.Errorf("missing )")
		}
		return v, nil
	case strings.HasPrefix(t, "'"):
		return ifVal{s: t[1:]}, nil
	case t == "true" || t == "false":
		return ifVal{b: t == "true", isB: true}, nil
	case p.peek() == "(":
		p.next()
		var args []ifVal
		for p.peek() != ")" {
			a, err := p.or()
			if err != nil {
				return a, err
			}
			args = append(args, a)
			if p.peek() == "," {
				p.next()
			}
		}
		p.next()
		switch t {
		case "always", "success":
			return ifVal{b: true, isB: true}, nil
		case "contains":
			if len(args) != 2 {
				return ifVal{}, fmt.Errorf("contains() wants 2 arguments")
			}
			if args[0].list {
				return ifVal{b: false, isB: true}, nil
			}
			return ifVal{b: strings.Contains(strings.ToLower(args[0].str()), strings.ToLower(args[1].str())), isB: true}, nil
		}
		return ifVal{}, fmt.Errorf("function %s() is not modelled", t)
	default:
		if t == "github.event.pull_request.labels.*.name" {
			return ifVal{list: true}, nil
		}
		s, err := p.resolve(t)
		return ifVal{s: s}, err
	}
}

func TestEvalIf(t *testing.T) {
	ctx := map[string]string{
		"github.event_name":                  "pull_request",
		"needs.changes.outputs.docs_only":    "true",
		"needs.changes.outputs.web_only":     "false",
		"needs.select.outputs.mode":          "full",
		"needs.preflight.result":             "success",
		"needs.changes.outputs.full_profile": "false",
	}
	resolve := func(p string) (string, error) {
		v, ok := ctx[p]
		if !ok {
			return "", fmt.Errorf("unmodelled %s", p)
		}
		return v, nil
	}
	cases := []struct {
		expr string
		want bool
	}{
		{"needs.changes.outputs.docs_only != 'true'", false},
		{"needs.changes.outputs.web_only != 'true'", true},
		{"github.event_name == 'pull_request' || github.event_name == 'merge_group'", true},
		{"needs.changes.outputs.docs_only != 'true' && (github.event_name == 'pull_request' || needs.select.outputs.mode == 'selected')", false},
		{"always() && needs.preflight.result == 'success' && !contains(github.event.pull_request.labels.*.name, 'ci:full')", true},
		{"${{ github.event_name == 'merge_group' }}", false},
		{"!(needs.changes.outputs.full_profile == 'true')", true},
		{"contains('it''s', 's')", true},
	}
	for _, c := range cases {
		got, err := evalIf(c.expr, resolve)
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		if got != c.want {
			t.Errorf("%s = %v, want %v", c.expr, got, c.want)
		}
	}
	if _, err := evalIf("github.base_ref == 'main'", resolve); err == nil {
		t.Error("an unmodelled context path must be an error, not ''")
	}
	if _, err := evalIf("startsWith(github.event_name, 'p')", resolve); err == nil {
		t.Error("an unmodelled function must be an error")
	}
}
