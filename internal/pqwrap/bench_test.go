package pqwrap

import (
	"bytes"
	"testing"
)

// Benchmarks for the design note's performance budget (§14). Numbers go in
// the session report, not in repo docs.
func BenchmarkWrap(b *testing.B) {
	for _, s := range allSuites {
		b.Run(s.String(), func(b *testing.B) {
			pub := testKey(b, s, "bench").PublicKey()
			key := bytes.Repeat([]byte{3}, 32)
			b.ReportMetric(float64(EnvelopeSize(s, 32)), "envelope-bytes")
			for b.Loop() {
				if _, err := Wrap(pub, PurposeDEK, []byte("ctx"), key); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkUnwrap(b *testing.B) {
	for _, s := range allSuites {
		b.Run(s.String(), func(b *testing.B) {
			priv := testKey(b, s, "bench")
			env, err := Wrap(priv.PublicKey(), PurposeDEK, []byte("ctx"), bytes.Repeat([]byte{3}, 32))
			if err != nil {
				b.Fatal(err)
			}
			for b.Loop() {
				if _, err := Unwrap(priv, PurposeDEK, []byte("ctx"), env); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPrivateKeyFromSeed(b *testing.B) {
	for _, s := range allSuites {
		b.Run(s.String(), func(b *testing.B) {
			seed := testSeed("bench")
			for b.Loop() {
				if _, err := NewPrivateKeyFromSeed(s, seed); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
