package azurefuzz

import "testing"

// TestOracleRedGreen validates each fatal oracle red/green, plus pins the
// truncation predicate to writeResponse's actual wire behaviour.

func TestOracleCanary_RedGreen(t *testing.T) {
	leaky := struct{ Token string }{Token: canaryToken}
	if r := evalOracles("x", nil, leaky, nil, false); len(r.findings) == 0 {
		t.Fatal("canary oracle GREEN on a leaking output — expected a finding")
	}
	if r := evalOracles("x", nil, nil, &stubErr{canaryCredExtra}, false); len(r.findings) == 0 {
		t.Fatal("canary oracle GREEN on a leaking error — expected a finding")
	}
	if r := evalOracles("x", nil, struct{ S string }{"public"}, &stubErr{"SecretNotFound"}, false); len(r.findings) != 0 {
		t.Fatalf("canary oracle RED on benign exchange: %v", r.findings)
	}
}

func TestOracleIgnoredReadError_RedGreen(t *testing.T) {
	if r := evalOracles("x", nil, struct{}{}, nil, true); len(r.findings) == 0 {
		t.Fatal("ignored-read-error oracle GREEN when a truncating final response produced success")
	}
	if r := evalOracles("x", nil, nil, &stubErr{"unexpected EOF"}, true); len(r.findings) != 0 {
		t.Fatalf("ignored-read-error oracle RED when client correctly errored: %v", r.findings)
	}
	if r := evalOracles("x", nil, struct{}{}, nil, false); len(r.findings) != 0 {
		t.Fatalf("ignored-read-error oracle RED on a complete response: %v", r.findings)
	}
}

func TestSpecTruncates_MirrorsWriteResponse(t *testing.T) {
	cases := []struct {
		name string
		s    respSpec
		want bool
	}{
		{"complete-empty-body-close", respSpec{status: 264, closeAfterBody: true}, false},
		{"chunked-complete-ignores-lyingLen", respSpec{status: 200, chunked: true, lyingLen: 1}, false},
		{"chunked-truncated", respSpec{status: 200, chunked: true, truncateInChunk: true, body: []byte("x")}, true},
		{"lying-content-length", respSpec{status: 200, lyingLen: 4096, body: []byte("short")}, true},
		{"204-no-body-ignores-lyingLen", respSpec{status: 204, lyingLen: 1}, false},
		{"304-no-body-ignores-lyingLen", respSpec{status: 304, lyingLen: 1}, false},
		{"1xx-no-body-ignores-lyingLen", respSpec{status: 100, lyingLen: 1}, false},
		{"raw-excluded", respSpec{raw: true, lyingLen: 4096}, false},
		{"plain-complete", respSpec{status: 200, body: []byte("{}")}, false},
	}
	for _, c := range cases {
		if got := specTruncates(c.s); got != c.want {
			t.Errorf("%s: specTruncates=%v want %v", c.name, got, c.want)
		}
	}
}

func TestOracleEcho_Informational(t *testing.T) {
	specs := []respSpec{{status: 404, body: []byte("server message echoed")}}
	r := evalOracles("x", specs, nil, &stubErr{"GET failed: server message echoed"}, false)
	if !r.echoed {
		t.Fatal("echo oracle did not flag server body copied into error")
	}
	if len(r.findings) != 0 {
		t.Fatalf("echo must be informational, not a finding: %v", r.findings)
	}
}

type stubErr struct{ s string }

func (e *stubErr) Error() string { return e.s }
