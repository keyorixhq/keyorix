package storage

import (
	"reflect"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestStorageBackends_SelectionTable pins CreateStorage's selection rules now that
// each backend declares itself in its own factory_<backend>.go: the same four
// storage.type values select the same two constructors, no name is claimed twice,
// and a blank or unknown type still gets the exact errors the old switch returned.
func TestStorageBackends_SelectionTable(t *testing.T) {
	createPostgres := reflect.ValueOf((*DefaultStorageFactory).createPostgresStorage).Pointer()
	createLocal := reflect.ValueOf((*DefaultStorageFactory).createLocalStorage).Pointer()
	want := map[string]uintptr{
		"postgres":   createPostgres,
		"postgresql": createPostgres,
		"local":      createLocal,
		"sqlite":     createLocal,
	}

	claimed := map[string]int{}
	for _, b := range storageBackends {
		for _, n := range b.names {
			claimed[n]++
			if n == "" {
				t.Errorf("a backend claims the blank storage.type; it must keep failing loudly (#G-blank-storage-default)")
			}
		}
	}
	for n, c := range claimed {
		if c != 1 {
			t.Errorf("storage.type %q is claimed by %d backends", n, c)
		}
		if _, ok := want[n]; !ok {
			t.Errorf("storage.type %q is selectable but not in this table: add it here and to config.Validate's storage.type switch", n)
		}
	}
	for name, fn := range want {
		var got uintptr
		for _, b := range storageBackends {
			for _, n := range b.names {
				if n == name {
					got = reflect.ValueOf(b.create).Pointer()
				}
			}
		}
		if got != fn {
			t.Errorf("storage.type %q selects the wrong constructor (or none)", name)
		}
	}

	f := &DefaultStorageFactory{}
	for typ, wantErr := range map[string]string{
		"":          `storage.type is not set: no storage configuration found -- specify "local", "postgres", or "postgresql" explicitly`,
		"remote":    `invalid storage.type "remote": must be one of "local", "postgres", or "postgresql"`,
		"postgress": `invalid storage.type "postgress": must be one of "local", "postgres", or "postgresql"`,
	} {
		cfg := &config.Config{}
		cfg.Storage.Type = typ
		if _, err := f.CreateStorage(cfg); err == nil || err.Error() != wantErr {
			t.Errorf("CreateStorage(type %q) error = %v, want %q", typ, err, wantErr)
		}
	}
}
