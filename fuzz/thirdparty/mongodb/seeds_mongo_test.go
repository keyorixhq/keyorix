package mongofuzz

import (
	"encoding/binary"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Seed corpus for FuzzMongoReply. The fuzz input is the wire reply from the
// opcode field onward (the fake server prepends messageLength/requestID/
// responseTo). Builders here produce valid OP_MSG / OP_COMPRESSED shapes plus
// known-interesting malformations (bad section lengths, checksum flag, bad
// compressed wrapper), all pinned to the mongo wire format (traced 2026-11-12).

// opMsgBody builds an OP_MSG body-from-opcode: [opcode:4=2013][flagBits:4]
// [section kind 0][bson doc].
func opMsgBody(flags uint32, doc []byte) []byte {
	out := make([]byte, 0, 9+len(doc))
	out = binary.LittleEndian.AppendUint32(out, opMSG)
	out = binary.LittleEndian.AppendUint32(out, flags)
	out = append(out, 0x00) // section kind 0: body
	out = append(out, doc...)
	return out
}

// opMsgBodyKind1 builds an OP_MSG with a kind-1 (document sequence) section:
// [opcode][flags][kind1][sectionSize:4][seqId cstring][docs...].
func opMsgBodyKind1(flags uint32, seqID string, docs ...[]byte) []byte {
	var sec []byte
	sec = append(sec, []byte(seqID)...)
	sec = append(sec, 0x00)
	for _, d := range docs {
		sec = append(sec, d...)
	}
	size := 4 + len(sec)
	out := make([]byte, 0)
	out = binary.LittleEndian.AppendUint32(out, opMSG)
	out = binary.LittleEndian.AppendUint32(out, flags)
	out = append(out, 0x01) // section kind 1
	out = binary.LittleEndian.AppendUint32(out, uint32(size))
	out = append(out, sec...)
	return out
}

// opCompressedBody wraps an inner OP_MSG body (flags-onward, i.e. without the
// inner opcode field) as OP_COMPRESSED with compressorId 0 (noop):
// [opcode:4=2012][originalOpcode:4][uncompressedSize:4][compressorId:1][data].
func opCompressedBody(originalOpcode uint32, uncompressedSize uint32, compressorID byte, data []byte) []byte {
	out := make([]byte, 0)
	out = binary.LittleEndian.AppendUint32(out, opCOMPRESSED)
	out = binary.LittleEndian.AppendUint32(out, originalOpcode)
	out = binary.LittleEndian.AppendUint32(out, uncompressedSize)
	out = append(out, compressorID)
	out = append(out, data...)
	return out
}

func okDoc() []byte {
	b, _ := bson.Marshal(bson.D{{Key: "ok", Value: 1.0}, {Key: "value", Value: "fine"}})
	return b
}

func errDoc(code int32, msg string) []byte {
	b, _ := bson.Marshal(bson.D{
		{Key: "ok", Value: 0.0},
		{Key: "code", Value: code},
		{Key: "errmsg", Value: msg},
	})
	return b
}

// cursorDoc builds a reply carrying a cursor firstBatch — the "cursor batches"
// lead.
func cursorDoc() []byte {
	b, _ := bson.Marshal(bson.D{
		{Key: "ok", Value: 1.0},
		{Key: "cursor", Value: bson.D{
			{Key: "id", Value: int64(0)},
			{Key: "ns", Value: "admin.$cmd"},
			{Key: "firstBatch", Value: bson.A{
				bson.D{{Key: "a", Value: 1}},
				bson.D{{Key: "b", Value: "two"}},
			}},
		}},
	})
	return b
}

const (
	flagChecksumPresent uint32 = 1 << 0
	flagMoreToCome      uint32 = 1 << 1
)

func mongoSeeds() [][]byte {
	// A noop-compressed OK reply: compressorId 0 => body is uncompressed inner
	// [flags:4][kind0][doc]. uncompressedSize = len of that inner payload.
	inner := func() []byte {
		b := make([]byte, 0)
		b = binary.LittleEndian.AppendUint32(b, 0) // flags
		b = append(b, 0x00)                        // kind 0
		b = append(b, okDoc()...)
		return b
	}()

	return [][]byte{
		opMsgBody(0, okDoc()),
		opMsgBody(0, errDoc(59, "no such command")),
		opMsgBody(0, cursorDoc()),
		opMsgBodyKind1(0, "documents", okDoc()),
		// checksum flag set but no checksum bytes appended
		opMsgBody(flagChecksumPresent, okDoc()),
		// moreToCome flag
		opMsgBody(flagMoreToCome, okDoc()),
		// noop-compressed OK
		opCompressedBody(opMSG, uint32(len(inner)), 0, inner),
		// OP_COMPRESSED declaring a huge uncompressedSize (clamped by the harness)
		opCompressedBody(opMSG, 0x7fffffff, 0, inner),
		// OP_MSG with a kind-1 section whose declared size is larger than sent
		func() []byte {
			b := opMsgBodyKind1(0, "documents", okDoc())
			// inflate the kind-1 sectionSize field (at offset 4+4+1 = 9)
			binary.LittleEndian.PutUint32(b[9:13], 0x00ffffff)
			return b
		}(),
		// bare opcode only
		func() []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, opMSG); return b }(),
		// empty
		{},
	}
}
