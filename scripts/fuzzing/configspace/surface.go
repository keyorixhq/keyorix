package configspace

import (
	"reflect"
	"sort"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
)

// SurfaceEntry is one YAML key of config.Config found by reflection.
type SurfaceEntry struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Secret bool   `json:"secret,omitempty"`
}

// Surface walks config.Config and lists every YAML key it can decode. It is the
// "whole surface" inventory; model.yaml is the curated, value-annotated subset.
func Surface() []SurfaceEntry {
	var out []SurfaceEntry
	walk(reflect.TypeFor[config.Config](), "", map[reflect.Type]int{}, &out)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func yamlName(f reflect.StructField) (name string, skip bool) {
	tag := f.Tag.Get("yaml")
	if tag == "-" {
		return "", true
	}
	name = strings.Split(tag, ",")[0]
	if name == "" {
		name = strings.ToLower(f.Name)
	}
	return name, false
}

func walk(t reflect.Type, prefix string, seen map[reflect.Type]int, out *[]SurfaceEntry) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		if seen[t] >= 2 {
			return
		}
		seen[t]++
		defer func() { seen[t]-- }()
		for f := range t.Fields() {
			if f.PkgPath != "" {
				continue
			}
			name, skip := yamlName(f)
			if skip {
				continue
			}
			p := name
			if prefix != "" {
				p = prefix + "." + name
			}
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			switch ft.Kind() {
			case reflect.Struct:
				walk(ft, p, seen, out)
			case reflect.Slice:
				et := ft.Elem()
				for et.Kind() == reflect.Pointer {
					et = et.Elem()
				}
				if et.Kind() == reflect.Struct {
					walk(et, p+"[]", seen, out)
				} else {
					*out = append(*out, SurfaceEntry{Path: p, Type: ft.String(), Secret: IsSecretPath(p)})
				}
			default:
				*out = append(*out, SurfaceEntry{Path: p, Type: ft.String(), Secret: IsSecretPath(p)})
			}
		}
	default:
		*out = append(*out, SurfaceEntry{Path: prefix, Type: t.String()})
	}
}

// lookupEffective returns the effective value of a dotted YAML path in cfg, using the
// yaml tags. ok is false when the path does not resolve to a scalar or []string leaf.
func lookupEffective(cfg *config.Config, path string) (val any, ok bool) {
	v := reflect.ValueOf(cfg).Elem()
	for seg := range strings.SplitSeq(path, ".") {
		for v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return nil, false
			}
			v = v.Elem()
		}
		if v.Kind() != reflect.Struct {
			return nil, false
		}
		found := false
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if f.PkgPath != "" {
				continue
			}
			name, skip := yamlName(f)
			if skip || name != seg {
				continue
			}
			v = v.Field(i)
			found = true
			break
		}
		if !found {
			return nil, false
		}
	}
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil, true
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Bool, reflect.String, reflect.Int, reflect.Int64, reflect.Int32:
		return v.Interface(), true
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.String {
			s := make([]string, v.Len())
			for i := range s {
				s[i] = v.Index(i).String()
			}
			return s, true
		}
	}
	return nil, false
}
