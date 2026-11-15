package awsfuzz

import "testing"

// TestOracleRedGreen validates each fatal oracle: a deliberately broken input
// must produce a finding (red), and a correct exchange must not (green).

func TestOracleCanary_RedGreen(t *testing.T) {
	// RED: an output struct whose fmt %+v contains the secret canary.
	leaky := struct{ Token string }{Token: canarySecretKey}
	if r := evalOracles("x", nil, leaky, nil, false); len(r.findings) == 0 {
		t.Fatal("canary oracle GREEN on a leaking output — expected a finding")
	}
	// RED via error string.
	if r := evalOracles("x", nil, nil, &stubErr{canaryToken}, false); len(r.findings) == 0 {
		t.Fatal("canary oracle GREEN on a leaking error — expected a finding")
	}
	// GREEN: benign output and error.
	if r := evalOracles("x", nil, struct{ S string }{"public"}, &stubErr{"ResourceNotFound"}, false); len(r.findings) != 0 {
		t.Fatalf("canary oracle RED on benign exchange: %v", r.findings)
	}
}

func TestOracleIgnoredReadError_RedGreen(t *testing.T) {
	// RED: the final response truncated but client reported success (err == nil).
	if r := evalOracles("x", nil, struct{}{}, nil, true); len(r.findings) == 0 {
		t.Fatal("ignored-read-error oracle GREEN when a truncating final response produced success")
	}
	// GREEN: final response truncated, client correctly errored.
	if r := evalOracles("x", nil, nil, &stubErr{"unexpected EOF"}, true); len(r.findings) != 0 {
		t.Fatalf("ignored-read-error oracle RED when client correctly errored: %v", r.findings)
	}
	// GREEN: final response NOT truncated and client returned success — fine.
	if r := evalOracles("x", nil, struct{}{}, nil, false); len(r.findings) != 0 {
		t.Fatalf("ignored-read-error oracle RED on a complete response: %v", r.findings)
	}
}

// TestSpecTruncates_MirrorsWriteResponse pins the oracle's truncation predicate
// to the actual wire behaviour of writeResponse (the two harness-bug crashers).
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
	specs := []respSpec{{status: 400, body: []byte("server message echoed")}}
	r := evalOracles("x", specs, nil, &stubErr{"api error: server message echoed"}, false)
	if !r.echoed {
		t.Fatal("echo oracle did not flag server body copied into error")
	}
	if len(r.findings) != 0 {
		t.Fatalf("echo must be informational, not a finding: %v", r.findings)
	}
}

type stubErr struct{ s string }

func (e *stubErr) Error() string { return e.s }
