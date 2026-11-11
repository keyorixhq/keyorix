package awsfuzz

import "testing"

// enc builds a fuzz-input byte slice matching decodeSpecs' wire format, so the
// seed corpus contains meaningful protocol exchanges (valid + known-bad) rather
// than only opaque blobs. Keep this in sync with decodeSpecs/reader.
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

// seedSpec mirrors the flag layout decodeSpecs reads.
type seedSpec struct {
	raw, closeAfterBody, chunked, truncateInChunk, extraHdr, lyingLen bool
	status                                                            int
	ctSel                                                             int
	hdr                                                               []byte
	body                                                              []byte
	lyingExtra                                                        int
}

func encodeSeeds(specs []seedSpec) []byte {
	e := &enc{}
	// count selector so that u8%4+1 == len(specs)
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
		// status: decoder computes 100 + u16%500
		e.u16((s.status - 100) & 0xffff)
		e.u8(s.ctSel)
		if s.extraHdr {
			e.lp(64, s.hdr)
		}
		e.lp(1<<16, s.body)
		if s.lyingLen {
			e.u16(s.lyingExtra)
		}
	}
	return e.b
}

func seedCorpus(f *testing.F) {
	// valid-looking JSON success
	f.Add(encodeSeeds([]seedSpec{{status: 200, ctSel: 0, body: []byte(`{"SecretString":"hello","ARN":"arn:aws:x","Name":"n"}`)}}))
	// valid empty object
	f.Add(encodeSeeds([]seedSpec{{status: 200, ctSel: 0, body: []byte(`{}`)}}))
	// AWS JSON error shape (echoes a server message)
	f.Add(encodeSeeds([]seedSpec{{status: 400, ctSel: 0, body: []byte(`{"__type":"ResourceNotFoundException","message":"server echo text here"}`)}}))
	// STS-style XML success
	f.Add(encodeSeeds([]seedSpec{{status: 200, ctSel: 2, body: []byte(`<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>AK</AccessKeyId><SecretAccessKey>s</SecretAccessKey><SessionToken>t</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`)}}))
	// STS XML error
	f.Add(encodeSeeds([]seedSpec{{status: 403, ctSel: 2, body: []byte(`<ErrorResponse><Error><Code>AccessDenied</Code><Message>denied echo</Message></Error></ErrorResponse>`)}}))
	// 500 then 200 — retry path
	f.Add(encodeSeeds([]seedSpec{
		{status: 500, ctSel: 0, body: []byte(`{"__type":"InternalFailure"}`)},
		{status: 200, ctSel: 0, body: []byte(`{"SecretString":"recovered"}`)},
	}))
	// 202 Accepted with a body
	f.Add(encodeSeeds([]seedSpec{{status: 202, ctSel: 0, body: []byte(`{"SecretString":"accepted?"}`)}}))
	// 206 Partial Content with error text
	f.Add(encodeSeeds([]seedSpec{{status: 206, ctSel: 0, body: []byte(`{"__type":"PartialThing","message":"partial echo"}`)}}))
	// redirect with a body (client must not follow)
	f.Add(encodeSeeds([]seedSpec{{status: 302, ctSel: 5, extraHdr: true, hdr: []byte("Location: http://169.254.169.254/"), body: []byte("moved")}}))
	// ignored-read-error: lying Content-Length, body shorter than declared
	f.Add(encodeSeeds([]seedSpec{{status: 200, ctSel: 0, lyingLen: true, lyingExtra: 4096, body: []byte(`{"SecretString":"trunc`)}}))
	// truncated chunked body
	f.Add(encodeSeeds([]seedSpec{{status: 200, ctSel: 0, chunked: true, truncateInChunk: true, body: []byte(`{"SecretString":"chunktrunc`)}}))
	// deeply nested JSON (parser stack)
	deep := []byte(`{"a":`)
	for i := 0; i < 2000; i++ {
		deep = append(deep, '[')
	}
	f.Add(encodeSeeds([]seedSpec{{status: 200, ctSel: 0, body: deep}}))
	// raw garbage framing
	f.Add(encodeSeeds([]seedSpec{{raw: true, body: []byte("HTTP/1.1 200\r\nContent-Length: 999999\r\n\r\nshort")}}))
	// empty input
	f.Add([]byte{})
}
