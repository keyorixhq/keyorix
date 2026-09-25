package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// -- No-panic fuzzing over arbitrary file/byte content (CLI-FUZZ target 3a) --

func FuzzParseDotenvContent(f *testing.F) {
	seeds := [][]byte{
		[]byte("KEY=value\n"),
		[]byte("# comment\nKEY='va''lue'\n"),
		[]byte("KEY=\"unterminated"),
		[]byte("=novalue\n"),
		[]byte("KEY=\n"),
		[]byte("\x00\x01binary\n"),
		[]byte("KEY=A=B\n"),
		{},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "f.env")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skipf("could not write fixture: %v", err)
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseDotenv panicked on %q: %v", data, r)
			}
		}()
		_, _ = parseDotenv(path) // an error is a valid outcome; a panic is not
	})
}

func FuzzParseJSONBytesContent(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{"KEY":"value"}`),
		[]byte(`{}`),
		[]byte(`not json`),
		[]byte(`{"KEY":123}`),
		[]byte(`{"KEY":null}`),
		[]byte(`{"KEY":{"nested":"object"}}`),
		[]byte(`[]`),
		[]byte(`"just a string"`),
		{},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseJSONBytes panicked on %q: %v", data, r)
			}
		}()
		_, _ = parseJSONBytes(data)
	})
}

func FuzzParseVaultContent(f *testing.F) {
	seeds := [][]byte{
		[]byte("secret/env-1/db:\n  value: pw\n"),
		[]byte("secret/env-1/db:\n  password: pw\n  username: app\n"),
		[]byte("not: [valid yaml"),
		[]byte(""),
		[]byte("just a scalar"),
		[]byte("secret/env-1/db: not-a-map\n"),
		[]byte("a: &anchor\n  b: *anchor\n"), // yaml anchor/alias, cheap billion-laughs shape
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "f.yaml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skipf("could not write fixture: %v", err)
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseVault panicked on %q: %v", data, r)
			}
		}()
		_, _ = parseVault(path)
	})
}

// -- Round-trip stability: parse(export(secret)) == secret for valid inputs (CLI-FUZZ
// target 3b). "Valid" means what the pipeline itself already treats as importable: a
// non-empty name/value that clears the same control-char gate validateImportedEntry
// applies on parse. --

func roundTripSkip(name, value string) bool {
	return name == "" || value == "" || keyHasControlChars(name) || valueHasDangerousControlChars(value)
}

func FuzzDotenvRoundTrip(f *testing.F) {
	f.Add("KEY", "value")
	f.Add("DB_PASSWORD", "p@ss w/ spaces")
	f.Add("API_KEY", "it's got an apostrophe")
	f.Add("MULTI", "line1\nline2")
	f.Add("A=B", "value")
	f.Add("#comment-looking", "value")

	f.Fuzz(func(t *testing.T, name, value string) {
		if roundTripSkip(name, value) {
			return
		}
		entries := []exportedSecret{{ID: 1, Name: name, Value: value}}
		var buf bytes.Buffer
		if err := writeDotenv(&buf, entries); err != nil {
			return // export-side refusal (e.g. name contains a newline) is a valid outcome
		}

		dir := t.TempDir()
		path := filepath.Join(dir, "rt.env")
		if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
			t.Skipf("could not write fixture: %v", err)
		}
		parsed, err := parseDotenv(path)
		if err != nil {
			t.Fatalf("round-trip parse failed for name=%q value=%q exported=%q: %v", name, value, buf.String(), err)
		}
		if len(parsed) != 1 || parsed[0].Name != name || parsed[0].Value != value {
			t.Fatalf("round-trip mismatch: wrote name=%q value=%q, exported=%q, reparsed=%+v", name, value, buf.String(), parsed)
		}
	})
}

func FuzzJSONRoundTrip(f *testing.F) {
	f.Add("KEY", "value")
	f.Add("DB_PASSWORD", "p@ss w/ spaces \"quoted\" and \\backslash")
	f.Add("unicode-key-café", "unicode-value-日本語")

	f.Fuzz(func(t *testing.T, name, value string) {
		if roundTripSkip(name, value) {
			return
		}
		entries := []exportedSecret{{ID: 1, Name: name, Value: value}}
		var buf bytes.Buffer
		if err := writeExportJSON(&buf, entries); err != nil {
			return // export-side refusal (e.g. invalid UTF-8) is a valid outcome
		}
		parsed, err := parseJSONBytes(buf.Bytes())
		if err != nil {
			t.Fatalf("round-trip parse failed for name=%q value=%q exported=%q: %v", name, value, buf.String(), err)
		}
		if len(parsed) != 1 || parsed[0].Name != name || parsed[0].Value != value {
			t.Fatalf("round-trip mismatch: wrote name=%q value=%q, exported=%q, reparsed=%+v", name, value, buf.String(), parsed)
		}
	})
}

func FuzzVaultRoundTrip(f *testing.F) {
	f.Add("db-password", "value")
	f.Add("has/a/slash", "value")
	f.Add("simple", "multi\nline\nvalue")

	f.Fuzz(func(t *testing.T, name, value string) {
		if roundTripSkip(name, value) {
			return
		}
		entries := []exportedSecret{{ID: 1, Name: name, Value: value}}
		var buf bytes.Buffer
		if err := writeVault(&buf, entries, 1); err != nil {
			return // export-side refusal (e.g. name contains '/') is a valid outcome
		}

		dir := t.TempDir()
		path := filepath.Join(dir, "rt.yaml")
		if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
			t.Skipf("could not write fixture: %v", err)
		}
		parsed, err := parseVault(path)
		if err != nil {
			t.Fatalf("round-trip parse failed for name=%q value=%q exported=%q: %v", name, value, buf.String(), err)
		}
		if len(parsed) != 1 || parsed[0].Name != name || parsed[0].Value != value {
			t.Fatalf("round-trip mismatch: wrote name=%q value=%q, exported=%q, reparsed=%+v", name, value, buf.String(), parsed)
		}
	})
}

// TestCheckImportFileSize_Boundary is CLI-FUZZ target 3c: an oversized import file must
// be rejected with a clear error, not read into memory. Uses sparse files (os.Truncate)
// so this stays cheap -- no real 100MiB write.
func TestCheckImportFileSize_Boundary(t *testing.T) {
	dir := t.TempDir()

	atLimit := filepath.Join(dir, "at-limit")
	if err := os.WriteFile(atLimit, nil, 0o600); err != nil {
		t.Fatalf("seed at-limit file: %v", err)
	}
	if err := os.Truncate(atLimit, maxImportFileBytes); err != nil {
		t.Fatalf("truncate at-limit file: %v", err)
	}
	if err := checkImportFileSize(atLimit); err != nil {
		t.Fatalf("a file exactly at the %d byte limit must be accepted, got: %v", maxImportFileBytes, err)
	}

	overLimit := filepath.Join(dir, "over-limit")
	if err := os.WriteFile(overLimit, nil, 0o600); err != nil {
		t.Fatalf("seed over-limit file: %v", err)
	}
	if err := os.Truncate(overLimit, maxImportFileBytes+1); err != nil {
		t.Fatalf("truncate over-limit file: %v", err)
	}
	if err := checkImportFileSize(overLimit); err == nil {
		t.Fatalf("a file one byte over the %d byte limit must be rejected", maxImportFileBytes)
	}
}
