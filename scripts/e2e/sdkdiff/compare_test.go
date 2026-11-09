package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestNormReqEncodingStyleIsNotADifference(t *testing.T) {
	a := normReq(Rec{Method: "GET", RequestURI: "/api/v1/secrets?environment=a+b%7E", Header: map[string][]string{"Authorization": {"Bearer x"}}})
	b := normReq(Rec{Method: "GET", RequestURI: "/api/v1/secrets?environment=a%20b~", Header: map[string][]string{"Authorization": {"Bearer x"}}})
	if !reflect.DeepEqual(a.Query, b.Query) || a.Path != b.Path {
		t.Fatalf("encoding-style variants must normalise equal: %+v vs %+v", a, b)
	}
	if a.RawQ == b.RawQ {
		t.Fatal("raw query kept for the informational counter")
	}
}

func TestNormReqDetectsDoubleEncodingAndTrailingSlash(t *testing.T) {
	a := normReq(Rec{Method: "GET", RequestURI: "/api/v1/secrets?environment=a%20b"})
	b := normReq(Rec{Method: "GET", RequestURI: "/api/v1/secrets?environment=a%2520b"})
	if reflect.DeepEqual(a.Query, b.Query) {
		t.Fatal("double encoding must differ")
	}
	c := normReq(Rec{Method: "GET", RequestURI: "/api/v1/projects/"})
	d := normReq(Rec{Method: "GET", RequestURI: "/api/v1/projects"})
	if c.Path == d.Path {
		t.Fatal("trailing slash is significant")
	}
}

func TestCanonJSONBytes(t *testing.T) {
	if canonJSONBytes([]byte(`{"b":1,"a":[1,2]}`)) != canonJSONBytes([]byte(` { "a" : [1,2] , "b":1 } `)) {
		t.Fatal("key order and whitespace must not matter")
	}
	if canonJSONBytes([]byte(`{"a":null}`)) == canonJSONBytes([]byte(`{"a":""}`)) {
		t.Fatal("null and empty string must differ")
	}
	if !strings.HasPrefix(canonJSONBytes([]byte("{x")), "RAW:") {
		t.Fatal("non-JSON compares as bytes")
	}
	if canonJSONBytes([]byte(`{"n":9007199254740993}`)) == canonJSONBytes([]byte(`{"n":9007199254740992}`)) {
		t.Fatal("big integers must keep their digits")
	}
}

func TestPartitionAndFindings(t *testing.T) {
	mk := func(sdk, auth string) view {
		return view{sdk: sdk, ok: true, value: "1", reqs: []NReq{{Method: "GET", Path: "/x", Auth: auth}}}
	}
	fs := compareStep("s", 0, "list_projects", []view{mk("go", "Bearer t"), mk("node", "bearer t"), mk("python", "Bearer t")})
	if len(fs) != 1 || fs[0].Cat != "W3" || blocksString(fs[0].Blocks) != "go,python/node" {
		t.Fatalf("want one W3 finding isolating node, got %+v", fs)
	}
	same := compareStep("s", 0, "list_projects", []view{mk("go", "Bearer t"), mk("node", "Bearer t")})
	if len(same) != 0 {
		t.Fatalf("identical views must be silent: %+v", same)
	}
}

func TestSkippedViewsAreNotCompared(t *testing.T) {
	a := view{sdk: "go", ok: true, value: "1"}
	b := view{sdk: "java", skip: "na"}
	if fs := compareStep("s", 0, "list_projects", []view{a, b}); len(fs) != 0 {
		t.Fatalf("N/A SDK must be excluded: %+v", fs)
	}
}

func TestErrorClassPartition(t *testing.T) {
	e := func(sdk, class string) view { return view{sdk: sdk, class: class, status: "404"} }
	fs := compareStep("s", 0, "list_environments", []view{e("go", "http"), e("node", "http"), e("python", "auth")})
	found := false
	for _, f := range fs {
		if f.Cat == "E1" && blocksString(f.Blocks) == "go,node/python" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want E1 isolating python: %+v", fs)
	}
}

func TestRedactionOracle(t *testing.T) {
	v := view{sdk: "node", class: "http", msg: "Server returned 500: CANARY-BODY-5d41402abc4b2a76",
		recs: []Rec{{RespBody: "CANARY-BODY-5d41402abc4b2a76"}}}
	fs := absoluteChecks("s", 0, Step{Op: "health"}, []view{v}, nil, func(string) string { return "tok" })
	if len(fs) != 1 || fs[0].Cat != "E3" {
		t.Fatalf("want E3: %+v", fs)
	}
}

func TestShimKeys(t *testing.T) {
	out := string(shimKeys([]byte(`{"data":{"projects":[{"id":1,"name":"a","x":1}]},"success":true}`)))
	if !strings.Contains(out, `"ID":1`) || !strings.Contains(out, `"Name":"a"`) || !strings.Contains(out, `"x":1`) {
		t.Fatalf("unexpected shim output %s", out)
	}
	if string(shimKeys([]byte("not json"))) != "not json" {
		t.Fatal("non-JSON passes through")
	}
}

func TestArgJSONRoundTrip(t *testing.T) {
	in := []Arg{S("a"), Null(), {Ref: &Ref{Step: 2, Path: "[0].id"}}}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out []Arg
	if err := json.Unmarshal(b, &out); err != nil || !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip failed: %s %v %+v", b, err, out)
	}
}

func TestDropStepRepairsRefs(t *testing.T) {
	sc := Scenario{Steps: []Step{{Op: "a"}, {Op: "b"}, {Op: "c", Args: []Arg{{Ref: &Ref{Step: 0, Path: "id"}}, {Ref: &Ref{Step: 1, Path: "id"}}}}}}
	o := dropStep(sc, 0)
	if o.Steps[1].Args[0].Str != "0" || o.Steps[1].Args[1].Ref.Step != 0 {
		t.Fatalf("refs not repaired: %+v", o.Steps[1].Args)
	}
}

func TestTwinsSplit(t *testing.T) {
	if !twinsSplit([][]string{{"go", "node"}, {"node@2"}}) {
		t.Fatal("node and node@2 split must be detected")
	}
	if twinsSplit([][]string{{"go", "go@2"}, {"node", "node@2"}}) {
		t.Fatal("twins together are fine")
	}
}

func TestGeneratorsAreDeterministic(t *testing.T) {
	a, _ := json.Marshal(genRandom(42))
	b, _ := json.Marshal(genRandom(42))
	if string(a) != string(b) {
		t.Fatal("same seed must give the same scenario")
	}
	if len(genMatrix()) < 500 {
		t.Fatal("matrix unexpectedly small")
	}
}

// FuzzNormalizers checks that the normalisers never panic and that canonical JSON is a fixed point.
func FuzzNormalizers(f *testing.F) {
	f.Add("/api/v1/secrets?environment=a%20b", `{"a":1}`)
	f.Add("/x?%zz=1&a", "{")
	f.Fuzz(func(t *testing.T, uri, body string) {
		_ = normReq(Rec{Method: "GET", RequestURI: uri, Body: []byte(body)})
		c := canonJSONBytes([]byte(body))
		if !strings.HasPrefix(c, "RAW:") && c != "" && canonJSONBytes([]byte(c)) != c {
			t.Fatalf("canonical JSON not a fixed point: %q -> %q", c, canonJSONBytes([]byte(c)))
		}
		_ = shimKeys([]byte(body))
	})
}
