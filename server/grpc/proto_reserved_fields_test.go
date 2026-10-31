package grpc_test

// proto_reserved_fields_test.go — INV-GRPC-05 (#2521).
//
// Invariant: CreateSecretRequest's field numbers 11–20 (ADR-105 §2,
// server/proto/keyorix.proto) are held for the phase-1 HTTP-parity governance
// fields and are never spent on anything else. Protobuf field numbers cannot
// be reused once a client has seen them, so a number spent on the wrong field
// is a permanent wire-contract defect.
//
// Why a test and not only `buf breaking`: buf.yaml configures `breaking: FILE`,
// but no CI workflow runs `buf breaking` (nor `buf` at all — only the
// Makefile's local `buf lint`), and wiring it in is a .github change. Even when
// run, buf breaking compares against a previous commit, so it judges any
// shrink of the reserved range the same way — it cannot tell the legitimate
// un-reserve-for-the-earmarked-field the proto comment anticipates from
// spending a held number on an unrelated field. This test encodes that intent
// instead: each number in 11–20 is either still reserved, or used by the one
// field it is earmarked for.
//
// Two independent views are checked so neither can drift alone: the compiled
// descriptor embedded in the generated pb package (what actually goes on the
// wire), and the keyorix.proto source (what the next `make proto` will
// generate).
//
// What this does NOT cover: any other message's reserved ranges, and type
// changes of an already-assigned field (buf breaking's job, still unwired).

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

const (
	heldFieldLo = 11
	heldFieldHi = 20
)

// earmarkedCreateSecretFields names the only field each held number may be
// un-reserved for (keyorix.proto's comment above `reserved 11 to 20`). 13–20
// are held for "the remaining phase-1 governance fields" without names yet:
// spending one requires naming it here, in review, first.
var earmarkedCreateSecretFields = map[protoreflect.FieldNumber]protoreflect.Name{
	11: "description",
	12: "classification",
}

// heldFieldViolations reports every way md breaks the hold on 11–20.
func heldFieldViolations(md protoreflect.MessageDescriptor) []string {
	var out []string
	reserved := md.ReservedRanges()
	for n := protoreflect.FieldNumber(heldFieldLo); n <= heldFieldHi; n++ {
		isReserved := reserved.Has(n)
		f := md.Fields().ByNumber(n)
		switch {
		case isReserved && f != nil:
			out = append(out, fmt.Sprintf("field number %d is both reserved and used by %q", n, f.Name()))
		case !isReserved && f == nil:
			out = append(out, fmt.Sprintf("field number %d is neither reserved nor used: the hold on 11–20 was dropped, so it is free to be spent on an unrelated field", n))
		case f != nil:
			if want, ok := earmarkedCreateSecretFields[n]; !ok || f.Name() != want {
				out = append(out, fmt.Sprintf("field number %d is used by %q, but it is held for %q (empty = not yet named) — field numbers can never be reused once spent", n, f.Name(), want))
			}
		}
	}
	return out
}

func TestCreateSecretRequest_HeldFieldNumbers_CompiledDescriptor(t *testing.T) {
	md := (&pb.CreateSecretRequest{}).ProtoReflect().Descriptor()
	require.Equal(t, protoreflect.FullName("keyorix.v1.CreateSecretRequest"), md.FullName())
	for _, v := range heldFieldViolations(md) {
		t.Error("CreateSecretRequest: " + v)
	}
}

// TestHeldFieldViolations_Calibration proves heldFieldViolations both ways
// against synthetic descriptors: green on the earmarked un-reserve, red on an
// unrelated field spending a held number and on a silently dropped hold.
// (The compiled pb descriptor cannot be mutated without regenerating, so the
// checker's red path is demonstrated here, permanently.)
func TestHeldFieldViolations_Calibration(t *testing.T) {
	build := func(t *testing.T, fields map[int32]string, reserved [][2]int32) protoreflect.MessageDescriptor {
		t.Helper()
		msg := &descriptorpb.DescriptorProto{Name: proto.String("CreateSecretRequest")}
		for num, name := range fields {
			msg.Field = append(msg.Field, &descriptorpb.FieldDescriptorProto{
				Name: proto.String(name), Number: proto.Int32(num),
				Type:  descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
				Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
			})
		}
		for _, r := range reserved {
			// DescriptorProto reserved ranges are end-exclusive.
			msg.ReservedRange = append(msg.ReservedRange, &descriptorpb.DescriptorProto_ReservedRange{Start: proto.Int32(r[0]), End: proto.Int32(r[1] + 1)})
		}
		fd, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
			Name: proto.String("calibration.proto"), Package: proto.String("calibration"),
			Syntax: proto.String("proto3"), MessageType: []*descriptorpb.DescriptorProto{msg},
		}, nil)
		require.NoError(t, err)
		return fd.Messages().Get(0)
	}

	assert.Empty(t, heldFieldViolations(build(t, map[int32]string{1: "name"}, [][2]int32{{11, 20}})),
		"today's shape (all of 11–20 reserved) must pass")
	assert.Empty(t, heldFieldViolations(build(t, map[int32]string{1: "name", 11: "description", 12: "classification"}, [][2]int32{{13, 20}})),
		"un-reserving 11/12 for their earmarked fields must pass")
	assert.Len(t, heldFieldViolations(build(t, map[int32]string{1: "name", 13: "owner"}, [][2]int32{{11, 12}, {14, 20}})), 1,
		"an unrelated field spending held number 13 must fail")
	assert.Len(t, heldFieldViolations(build(t, map[int32]string{1: "name", 11: "classification"}, [][2]int32{{12, 20}})), 1,
		"an earmarked field on the wrong number must fail")
	assert.Len(t, heldFieldViolations(build(t, map[int32]string{1: "name"}, nil)), heldFieldHi-heldFieldLo+1,
		"dropping the reserved statement must fail for every held number")
}

var (
	createSecretMsgRe = regexp.MustCompile(`(?s)message CreateSecretRequest \{(.*?)\n\}`)
	reservedRangeRe   = regexp.MustCompile(`(?m)^\s*reserved\s+([^;]+);`)
	fieldDeclRe       = regexp.MustCompile(`(?m)^\s*(?:optional\s+|repeated\s+)?[\w.<>, ]+\s+(\w+)\s*=\s*(\d+)\s*(?:\[[^\]]*\]\s*)?;`)
)

// protoSourceViolations is the source-text view of the hold on 11–20. It parses
// the CreateSecretRequest message out of src (the text of keyorix.proto) and
// reports every way it breaks the hold, in the same terms as
// heldFieldViolations.
//
// Forms the parser recognises (the list a reviewer should check it against):
//   - `//` line comments and `/* */` block comments are removed first, from the
//     whole file and ignoring comment markers inside string literals, so a
//     comment that merely says "reserved 11 to 20;" or "message
//     CreateSecretRequest {" is never read as a declaration;
//   - a `reserved` statement that starts its line, on one or several lines,
//     holding numbers (`reserved 4;`), ranges (`reserved 4 to 9;`,
//     `reserved 15 to max;`) and a comma list of both;
//   - names in a reserved statement (`reserved "name";`) are skipped: they hold
//     no number. A reserved item that is neither a number, a range nor a
//     quoted name is an error (fail closed), not silently ignored;
//   - field declarations on their own line, with optional `optional` /
//     `repeated`, a scalar, message, enum or `map<K, V>` type, and optional
//     `[field options]` before the `;` (also inside a `oneof` block).
//
// Forms it does NOT recognise: a `reserved` statement that follows another
// statement on the same line (it is then read as absent, so the check reports
// the hold dropped: fails closed); several field declarations on one line
// (only the first is seen); `extensions` ranges, which do not hold a number
// against field use; editions-syntax `reserved foo;` bare names.
func protoSourceViolations(src string) ([]string, error) {
	m := createSecretMsgRe.FindStringSubmatch(stripProtoComments(src))
	if m == nil {
		return nil, fmt.Errorf("message CreateSecretRequest not found")
	}
	body := m[1]

	type span struct{ lo, hi int }
	var reservedSpans []span
	for _, r := range reservedRangeRe.FindAllStringSubmatch(body, -1) {
		for part := range strings.SplitSeq(r[1], ",") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, `"`) || strings.HasPrefix(part, `'`) {
				continue // a reserved name holds no number
			}
			if lo, hi, ok := strings.Cut(part, " to "); ok {
				l, err1 := strconv.Atoi(strings.TrimSpace(lo))
				hi = strings.TrimSpace(hi)
				h, err2 := strconv.Atoi(hi)
				if hi == "max" {
					h, err2 = math.MaxInt32, nil
				}
				if err1 != nil || err2 != nil {
					return nil, fmt.Errorf("unparsed reserved range %q", part)
				}
				reservedSpans = append(reservedSpans, span{l, h})
			} else if n, err := strconv.Atoi(part); err == nil {
				reservedSpans = append(reservedSpans, span{n, n})
			} else {
				return nil, fmt.Errorf("unparsed reserved item %q", part)
			}
		}
	}
	isReserved := func(n int) bool {
		for _, s := range reservedSpans {
			if n >= s.lo && n <= s.hi {
				return true
			}
		}
		return false
	}
	used := map[int]string{}
	for _, f := range fieldDeclRe.FindAllStringSubmatch(body, -1) {
		n, _ := strconv.Atoi(f[2])
		used[n] = f[1]
	}
	if len(used) == 0 {
		return nil, fmt.Errorf("parsed zero field declarations from CreateSecretRequest — the parser broke")
	}

	var out []string
	for n := heldFieldLo; n <= heldFieldHi; n++ {
		name, isUsed := used[n]
		switch {
		case isReserved(n) && isUsed:
			out = append(out, fmt.Sprintf("field number %d is both reserved and used by %q", n, name))
		case !isReserved(n) && !isUsed:
			out = append(out, fmt.Sprintf("CreateSecretRequest field number %d is neither reserved nor used — the hold on 11–20 was dropped", n))
		case isUsed:
			if want, ok := earmarkedCreateSecretFields[protoreflect.FieldNumber(n)]; !ok || name != string(want) {
				out = append(out, fmt.Sprintf("CreateSecretRequest field number %d is used by %q, but it is held for %q (empty = not yet named)", n, name, want))
			}
		}
	}
	return out, nil
}

func TestCreateSecretRequest_HeldFieldNumbers_ProtoSource(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "proto", "keyorix.proto"))
	require.NoError(t, err)

	violations, err := protoSourceViolations(string(src))
	require.NoError(t, err, "keyorix.proto")
	for _, v := range violations {
		t.Error("keyorix.proto: " + v)
	}
}

// TestProtoSourceViolations_Calibration feeds protoSourceViolations small
// planted proto texts: green on today's shape, red when a held number is
// removed without a `reserved` entry, and one case per blind spot named in
// protoSourceViolations' doc comment.
func TestProtoSourceViolations_Calibration(t *testing.T) {
	const fields = "  string name = 1;\n  string value = 2;\n"
	msg := func(body string) string { return "message CreateSecretRequest {\n" + fields + body + "}\n" }

	t.Run("all of 11-20 reserved passes", func(t *testing.T) {
		v, err := protoSourceViolations(msg("  reserved 11 to 20;\n"))
		require.NoError(t, err)
		assert.Empty(t, v)
	})
	t.Run("earmarked un-reserve passes", func(t *testing.T) {
		v, err := protoSourceViolations(msg("  string description = 11;\n  string classification = 12;\n  reserved 13 to 20;\n"))
		require.NoError(t, err)
		assert.Empty(t, v)
	})
	t.Run("number removed without a reserved entry fails", func(t *testing.T) {
		// 13 dropped from the reserved range: 11–12 and 14–20 stay reserved.
		v, err := protoSourceViolations(msg("  reserved 11 to 12;\n  reserved 14 to 20;\n"))
		require.NoError(t, err)
		require.Len(t, v, 1)
		assert.Contains(t, v[0], "field number 13 is neither reserved nor used")
	})
	t.Run("same text with the reserved entry restored passes", func(t *testing.T) {
		v, err := protoSourceViolations(msg("  reserved 11 to 12;\n  reserved 13;\n  reserved 14 to 20;\n"))
		require.NoError(t, err)
		assert.Empty(t, v)
	})
	t.Run("unrelated field on a held number fails", func(t *testing.T) {
		v, err := protoSourceViolations(msg("  string owner = 13;\n  reserved 11 to 12;\n  reserved 14 to 20;\n"))
		require.NoError(t, err)
		require.Len(t, v, 1)
		assert.Contains(t, v[0], `used by "owner"`)
	})
	t.Run("field with options on a held number is still seen", func(t *testing.T) {
		v, err := protoSourceViolations(msg("  string owner = 13 [deprecated = true];\n  reserved 11 to 12;\n  reserved 14 to 20;\n"))
		require.NoError(t, err)
		require.Len(t, v, 1)
		assert.Contains(t, v[0], `used by "owner"`)
	})

	// Blind spots of a text parser.
	t.Run("line comment saying reserved does not count", func(t *testing.T) {
		v, err := protoSourceViolations(msg("  // reserved 11 to 20;\n"))
		require.NoError(t, err)
		assert.Len(t, v, heldFieldHi-heldFieldLo+1)
	})
	t.Run("block comment saying reserved does not count", func(t *testing.T) {
		v, err := protoSourceViolations(msg("  /*\n  reserved 11 to 20;\n  */\n"))
		require.NoError(t, err)
		assert.Len(t, v, heldFieldHi-heldFieldLo+1)
	})
	t.Run("commented-out message header does not hide the real one", func(t *testing.T) {
		src := "// message CreateSecretRequest {\n//   reserved 11 to 20;\n// }\n" + msg("")
		v, err := protoSourceViolations(src)
		require.NoError(t, err)
		assert.Len(t, v, heldFieldHi-heldFieldLo+1)
	})
	t.Run("trailing comment on a reserved line still counts", func(t *testing.T) {
		v, err := protoSourceViolations(msg("  reserved 11 to 20; // phase-1 governance\n"))
		require.NoError(t, err)
		assert.Empty(t, v)
	})
	t.Run("range to max covers the held numbers", func(t *testing.T) {
		v, err := protoSourceViolations(msg("  reserved 11 to max;\n"))
		require.NoError(t, err)
		assert.Empty(t, v)
	})
	t.Run("mixed numbers, ranges and names", func(t *testing.T) {
		v, err := protoSourceViolations(msg("  reserved 11, 12 to 15,\n    16 to 20;\n  reserved \"old_name\", \"other\";\n"))
		require.NoError(t, err)
		assert.Empty(t, v)
	})
	t.Run("reserved name alone holds no number", func(t *testing.T) {
		v, err := protoSourceViolations(msg("  reserved \"description\";\n"))
		require.NoError(t, err)
		assert.Len(t, v, heldFieldHi-heldFieldLo+1)
	})
	t.Run("short range 4 to 9 outside the held numbers changes nothing", func(t *testing.T) {
		v, err := protoSourceViolations(msg("  reserved 4 to 9;\n  reserved 11 to 20;\n"))
		require.NoError(t, err)
		assert.Empty(t, v)
	})
	t.Run("unparseable reserved item is an error, not ignored", func(t *testing.T) {
		_, err := protoSourceViolations(msg("  reserved 11 to twenty;\n"))
		assert.Error(t, err)
	})
	t.Run("reserved after another statement on the same line fails closed", func(t *testing.T) {
		v, err := protoSourceViolations(msg("  string tail = 3; reserved 11 to 20;\n"))
		require.NoError(t, err)
		assert.Len(t, v, heldFieldHi-heldFieldLo+1, "documented as not recognised: reads as absent")
	})
	t.Run("comment marker inside a reserved name string is not a comment", func(t *testing.T) {
		v, err := protoSourceViolations(msg("  reserved \"a//b\";\n  reserved 11 to 20;\n"))
		require.NoError(t, err)
		assert.Empty(t, v)
	})
}

// stripProtoComments removes `//` and `/* */` comments, keeping newlines (so
// line structure survives) and leaving string literals untouched.
func stripProtoComments(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		switch {
		case s[i] == '"' || s[i] == '\'':
			q := s[i]
			j := i + 1
			for j < len(s) && s[j] != q && s[j] != '\n' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			j = min(j+1, len(s))
			b.WriteString(s[i:j])
			i = j
		case strings.HasPrefix(s[i:], "//"):
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case strings.HasPrefix(s[i:], "/*"):
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return b.String() // unterminated: drop the rest (fails closed)
			}
			b.WriteString(strings.Repeat("\n", strings.Count(s[i:i+2+end+2], "\n")))
			i += 2 + end + 2
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}
