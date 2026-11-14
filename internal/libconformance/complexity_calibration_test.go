package libconformance

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/complexity"
	"github.com/keyorixhq/keyorix/internal/identity"
)

// TestComplexityCalibration logs, for each parser, the measured cost of a
// legitimate-large input and a pathological input, as bytes-allocated per input
// byte. It asserts nothing (it is a calibration/measurement run
// recording how the budgets were derived from these numbers); run with -v to read the
// table. It is also where a real super-linear blow-up would show up as a wildly
// high ratio, before the fuzzer is even started.
func TestComplexityCalibration(t *testing.T) {
	if testing.Short() {
		t.Skip("calibration allocates up to a few hundred MiB; skipped in -short")
	}
	type sample struct {
		name  string
		input []byte
		run   func([]byte) complexity.Cost
	}

	yamlRun := func(b []byte) complexity.Cost {
		return complexity.Measure(func() { var v any; _ = yaml.Unmarshal(b, &v) })
	}
	etreeRun := func(b []byte) complexity.Cost {
		return complexity.Measure(func() { d := etree.NewDocument(); _ = d.ReadFromBytes(b) })
	}
	parser := jwt.NewParser()
	jwtRun := func(b []byte) complexity.Cost {
		return complexity.Measure(func() { var c jwt.MapClaims; _, _, _ = parser.ParseUnverified(string(b), &c) })
	}
	pbRun := func(b []byte) complexity.Cost {
		return complexity.Measure(func() { _ = proto.Unmarshal(b, &structpb.Struct{}) })
	}
	idRun := func(b []byte) complexity.Cost {
		return complexity.Measure(func() { _, _ = identity.NewFoldedName(string(b)); _, _ = identity.NewAddressName(string(b)) })
	}

	samples := []sample{
		// yaml: a large legitimate doc (DISTINCT keys) vs a billion-laughs alias
		// bomb. See TestYAMLDuplicateKeyQuadratic for the duplicate-key O(n^2).
		{"yaml/legit-distinct", yamlDistinct(4000), yamlRun},
		{"yaml/laughs", yamlBomb(9), yamlRun},       // 9 levels of x2 fan-out
		{"yaml/laughs-deep", yamlBomb(15), yamlRun}, // 15 levels -> 2^15 nodes if unbounded
		// etree: legit vs deep-nest vs attribute-bomb.
		{"etree/legit-64k", xmlFlat(8000), etreeRun},
		{"etree/deep-nest", xmlDeep(16 << 10), etreeRun},
		{"etree/attr-bomb", xmlAttrs(16 << 10), etreeRun},
		// jwt: legit claims vs nested-array claims.
		{"jwt/legit", jwtToken(`{"sub":"a","aud":"b","exp":123}`), jwtRun},
		{"jwt/nested", jwtToken("[" + strings.Repeat("[", 5000) + strings.Repeat("]", 5000)), jwtRun},
		// protobuf: many unknown fields vs nested messages.
		{"pb/unknown-flat", pbUnknownFields(8000), pbRun},
		{"pb/nested", pbNested(90), pbRun},
		// identity: ascii vs stacked combining marks.
		{"id/ascii-16k", []byte(strings.Repeat("a", 16<<10)), idRun},
		{"id/combining", []byte(strings.Repeat("é̀̂̃", 3000)), idRun},
	}

	t.Logf("%-20s %10s %10s %12s %10s", "sample", "inBytes", "alloc", "alloc/byte", "wall")
	for _, s := range samples {
		c := s.run(s.input)
		perByte := 0.0
		if len(s.input) > 0 {
			perByte = float64(c.AllocBytes) / float64(len(s.input))
		}
		t.Logf("%-20s %10d %10d %12.2f %10s", s.name, len(s.input), c.AllocBytes, perByte, c.Wall)
	}
}

// yamlBomb builds a billion-laughs document with `levels` anchors, each a
// 2-element list referencing the previous anchor twice. If yaml.v3's alias
// budget is absent, the decoded structure has ~2^levels leaves.
func yamlBomb(levels int) []byte {
	var b strings.Builder
	b.WriteString("a0: &a0 \"lol\"\n")
	for i := 1; i < levels; i++ {
		fmt.Fprintf(&b, "a%d: &a%d [*a%d,*a%d]\n", i, i, i-1, i-1)
	}
	fmt.Fprintf(&b, "top: [*a%d,*a%d]\n", levels-1, levels-1)
	return []byte(b.String())
}

// yamlDistinct builds a mapping of n distinct keys — the legitimate large-doc
// baseline (linear cost), contrast with the duplicate-key quadratic.
func yamlDistinct(n int) []byte {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "k%d: v\n", i)
	}
	return []byte(b.String())
}

func xmlFlat(n int) []byte {
	var b strings.Builder
	b.WriteString("<r>")
	for range n {
		b.WriteString("<e>x</e>")
	}
	b.WriteString("</r>")
	return []byte(b.String())
}

func xmlDeep(n int) []byte {
	var b strings.Builder
	for range n {
		b.WriteString("<a>")
	}
	for range n {
		b.WriteString("</a>")
	}
	return []byte(b.String())
}

func xmlAttrs(n int) []byte {
	var b strings.Builder
	b.WriteString("<r")
	for i := range n {
		fmt.Fprintf(&b, " a%d=\"1\"", i)
	}
	b.WriteString("/>")
	return []byte(b.String())
}

func jwtToken(claimsJSON string) []byte {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	cl := base64.RawURLEncoding.EncodeToString([]byte(claimsJSON))
	return []byte(hdr + "." + cl + ".")
}

// pbUnknownFields builds a protobuf wire message of n varint fields with high
// field numbers (unknown to structpb.Struct), each 2-3 bytes.
func pbUnknownFields(n int) []byte {
	var b []byte
	for i := 1; i <= n; i++ {
		// tag = (field<<3)|wiretype(0=varint); use field numbers well past Struct's.
		field := uint64(1000 + i)
		tag := field<<3
		b = appendVarint(b, tag)
		b = appendVarint(b, 1)
	}
	return b
}

// pbNested builds depth nested length-delimited messages (field 1, wiretype 2).
func pbNested(depth int) []byte {
	inner := []byte{}
	for range depth {
		var framed []byte
		framed = appendVarint(framed, 1<<3|2) // field 1, len-delimited
		framed = appendVarint(framed, uint64(len(inner)))
		framed = append(framed, inner...)
		inner = framed
	}
	return inner
}

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}
