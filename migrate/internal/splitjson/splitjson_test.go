package splitjson

import "testing"

func TestObject_DecodesStringFieldsInSortedOrder(t *testing.T) {
	fields, ok := Object(`{"username":"alice","password":"hunter2"}`)
	if !ok {
		t.Fatal("Object returned ok=false for a valid JSON object")
	}
	if len(fields) != 2 || fields[0].Key != "password" || fields[1].Key != "username" {
		t.Fatalf("fields = %+v, want [password username] in sorted order", fields)
	}
	if fields[0].Value != "hunter2" || fields[1].Value != "alice" {
		t.Fatalf("fields = %+v, want unquoted string values", fields)
	}
}

func TestObject_NonStringValuesKeptAsCompactJSON(t *testing.T) {
	fields, ok := Object(`{"count":3,"active":true}`)
	if !ok {
		t.Fatal("Object returned ok=false")
	}
	got := map[string]string{}
	for _, f := range fields {
		got[f.Key] = f.Value
	}
	if got["count"] != "3" || got["active"] != "true" {
		t.Errorf("fields = %+v, want count=3 active=true", got)
	}
}

func TestObject_EmptyAndNullValuesSkipped(t *testing.T) {
	fields, ok := Object(`{"a":"","b":null,"c":"kept"}`)
	if !ok {
		t.Fatal("Object returned ok=false")
	}
	if len(fields) != 1 || fields[0].Key != "c" {
		t.Fatalf("fields = %+v, want only key c", fields)
	}
}

func TestObject_NonObjectReturnsNotOK(t *testing.T) {
	for _, v := range []string{`"plain string"`, `[1,2,3]`, `42`, `not json at all`, `{}`} {
		if _, ok := Object(v); ok {
			t.Errorf("Object(%q) returned ok=true, want false", v)
		}
	}
}
