package azurefuzz

import "testing"

// enc builds a fuzz-input byte slice matching decodeSpecs' wire format, so the
// seed corpus contains meaningful Key Vault exchanges (valid + challenge flow +
// known-bad) rather than opaque blobs. Keep in sync with decodeSpecs/reader.
type enc struct{ b []byte }

func (e *enc) u8(v int)  { e.b = append(e.b, byte(v)) }
func (e *enc) u16(v int) { e.b = append(e.b, byte(v), byte(v>>8)) }
func (e *enc) lp(max int, p []byte) {
	if len(p) > max {
		p = p[:max]
	}
	e.u16(len(p))
	e.b = append(e.b, p...)
}

type seedSpec struct {
	raw, closeAfterBody, chunked, truncateInChunk, extraHdr, lyingLen bool
	status                                                            int
	ctSel                                                             int
	hdr                                                               []byte // WWW-Authenticate value
	body                                                              []byte
	lyingExtra                                                        int
}

func encodeSeeds(specs []seedSpec) []byte {
	e := &enc{}
	e.u8((len(specs) - 1) & 0x03)
	for _, s := range specs {
		flags := 0
		if s.raw {
			flags |= 0x01
		}
		if s.closeAfterBody {
			flags |= 0x02
		}
		if s.chunked {
			flags |= 0x04
		}
		if s.truncateInChunk {
			flags |= 0x08
		}
		if s.extraHdr {
			flags |= 0x10
		}
		if s.lyingLen {
			flags |= 0x20
		}
		e.u8(flags)
		e.u16((s.status - 100) & 0xffff)
		e.u8(s.ctSel)
		if s.extraHdr {
			e.lp(256, s.hdr) // decoder reads lenPrefixed(256) for WWW-Authenticate
		}
		e.lp(1<<16, s.body)
		if s.lyingLen {
			e.u16(s.lyingExtra)
		}
	}
	return e.b
}

const (
	ctJSON = 3 // "application/json" in fakeserver.go's cts list
	ctXML  = 2
)

// a well-formed Key Vault challenge (what a real vault returns on the first,
// unauthenticated request).
var validChallenge = []byte(`Bearer authorization="https://login.microsoftonline.com/common/oauth2/authorize", resource="https://vault.azure.net"`)

func seedCorpus(f *testing.F) {
	secretBody := []byte(`{"value":"topsecret","id":"https://v.vault.azure.net/secrets/n/v","attributes":{"enabled":true}}`)
	// valid 200 secret
	f.Add(encodeSeeds([]seedSpec{{status: 200, ctSel: ctJSON, body: secretBody}}))
	// challenge flow: 401 + WWW-Authenticate, then 200 secret
	f.Add(encodeSeeds([]seedSpec{
		{status: 401, ctSel: ctJSON, extraHdr: true, hdr: validChallenge, body: []byte(`{"error":{"code":"Unauthorized","message":"challenge"}}`)},
		{status: 200, ctSel: ctJSON, body: secretBody},
	}))
	// malformed challenge values (challenge parser)
	for _, ch := range [][]byte{
		[]byte(`Bearer`),
		[]byte(`Bearer authorization=`),
		[]byte(`Bearer authorization="", resource=""`),
		[]byte(`Bearer authorization="not a url", resource="also not"`),
		[]byte(`Bearer realm="x", authorization_uri="https://login/tenant", resource="r"`),
		[]byte(`Bearer scope="https://vault.azure.net/.default" authorization="https://login/t"`),
		[]byte(`Pop something=weird`),
		[]byte(`Bearer authorization="https://login/t", resource="https://vault.azure.net", extra="` + string(make([]byte, 100)) + `"`),
	} {
		f.Add(encodeSeeds([]seedSpec{
			{status: 401, ctSel: ctJSON, extraHdr: true, hdr: ch, body: []byte(`{"error":{"code":"x","message":"y"}}`)},
			{status: 200, ctSel: ctJSON, body: secretBody},
		}))
	}
	// empty value (SDK returns non-nil *"" style)
	f.Add(encodeSeeds([]seedSpec{{status: 200, ctSel: ctJSON, body: []byte(`{"value":""}`)}}))
	// Key Vault error shape
	f.Add(encodeSeeds([]seedSpec{{status: 404, ctSel: ctJSON, body: []byte(`{"error":{"code":"SecretNotFound","message":"server echo text"}}`)}}))
	// 429 throttling then 200 (retry path)
	f.Add(encodeSeeds([]seedSpec{
		{status: 429, ctSel: ctJSON, body: []byte(`{"error":{"code":"Throttled"}}`)},
		{status: 200, ctSel: ctJSON, body: secretBody},
	}))
	// 202 and 206 with bodies
	f.Add(encodeSeeds([]seedSpec{{status: 202, ctSel: ctJSON, body: secretBody}}))
	f.Add(encodeSeeds([]seedSpec{{status: 206, ctSel: ctJSON, body: []byte(`{"value":"partial"}`)}}))
	// redirect with Location
	f.Add(encodeSeeds([]seedSpec{{status: 302, ctSel: ctJSON, extraHdr: true, hdr: []byte("ignored"), body: []byte("moved")}}))
	// XML body where JSON expected
	f.Add(encodeSeeds([]seedSpec{{status: 200, ctSel: ctXML, body: []byte(`<secret><value>x</value></secret>`)}}))
	// deeply nested JSON
	deep := []byte(`{"value":`)
	for i := 0; i < 2000; i++ {
		deep = append(deep, '[')
	}
	f.Add(encodeSeeds([]seedSpec{{status: 200, ctSel: ctJSON, body: deep}}))
	// lying Content-Length (truncation)
	f.Add(encodeSeeds([]seedSpec{{status: 200, ctSel: ctJSON, lyingLen: true, lyingExtra: 4096, body: []byte(`{"value":"trunc`)}}))
	// truncated chunk
	f.Add(encodeSeeds([]seedSpec{{status: 200, ctSel: ctJSON, chunked: true, truncateInChunk: true, body: []byte(`{"value":"chunktrunc`)}}))
	// 204 no-body with lying length (must NOT be flagged as truncation)
	f.Add(encodeSeeds([]seedSpec{{status: 204, ctSel: ctJSON, lyingLen: true, lyingExtra: 10}}))
	// raw garbage framing
	f.Add(encodeSeeds([]seedSpec{{raw: true, body: []byte("HTTP/1.1 200\r\nContent-Length: 999999\r\n\r\nshort")}}))
	// empty input
	f.Add([]byte{})
}
