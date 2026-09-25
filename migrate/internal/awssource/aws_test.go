package awssource

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// fakeSM is an in-process smAPI fake — no network, no real AWS account. secrets is keyed by
// secret name; pages splits ListSecrets into successive pages by index to exercise pagination.
type fakeSM struct {
	pages     [][]types.SecretListEntry
	secrets   map[string]*secretsmanager.GetSecretValueOutput
	getErr    map[string]error
	listCalls int
	getCalls  []string
}

func (f *fakeSM) ListSecrets(_ context.Context, in *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	f.listCalls++
	idx := 0
	if in.NextToken != nil {
		var err error
		idx, err = parsePageToken(*in.NextToken)
		if err != nil {
			return nil, err
		}
	}
	out := &secretsmanager.ListSecretsOutput{SecretList: f.pages[idx]}
	if idx+1 < len(f.pages) {
		out.NextToken = aws.String(pageToken(idx + 1))
	}
	return out, nil
}

func (f *fakeSM) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	name := aws.ToString(in.SecretId)
	f.getCalls = append(f.getCalls, name)
	if err, ok := f.getErr[name]; ok {
		return nil, err
	}
	if out, ok := f.secrets[name]; ok {
		return out, nil
	}
	return nil, errors.New("fakeSM: no such secret")
}

func pageToken(idx int) string             { return string(rune('a' + idx)) }
func parsePageToken(s string) (int, error) { return int(s[0] - 'a'), nil }

func newClientWithFake(f *fakeSM) *Client {
	c := New(Config{})
	c.newClient = func(context.Context) (smAPI, error) { return f, nil }
	return c
}

func TestList_PaginatesAcrossMultiplePages(t *testing.T) {
	f := &fakeSM{
		pages: [][]types.SecretListEntry{
			{{Name: aws.String("s1")}},
			{{Name: aws.String("s2")}},
		},
		secrets: map[string]*secretsmanager.GetSecretValueOutput{
			"s1": {SecretString: aws.String("v1")},
			"s2": {SecretString: aws.String("v2")},
		},
	}
	c := newClientWithFake(f)
	entries, skipped, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped = %+v, want none", skipped)
	}
	if f.listCalls != 2 {
		t.Errorf("ListSecrets called %d times, want 2 (one per page)", f.listCalls)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %+v, want 2", entries)
	}
}

func TestList_NamePrefixFilters(t *testing.T) {
	f := &fakeSM{
		pages: [][]types.SecretListEntry{{{Name: aws.String("team-a/db")}, {Name: aws.String("team-b/db")}}},
		secrets: map[string]*secretsmanager.GetSecretValueOutput{
			"team-a/db": {SecretString: aws.String("v1")},
			"team-b/db": {SecretString: aws.String("v2")},
		},
	}
	c := New(Config{NamePrefix: "team-a/"})
	c.newClient = func(context.Context) (smAPI, error) { return f, nil }
	entries, _, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].RawName != "team-a/db" {
		t.Fatalf("entries = %+v, want only team-a/db", entries)
	}
	if len(f.getCalls) != 1 {
		t.Errorf("GetSecretValue called for %v, want only the matching secret fetched", f.getCalls)
	}
}

// TestReadSecret_EmptyStringValueIsSkipped locks in the same bug class
// internal/connect/awssm.go's GetSecret was fixed for: SecretString != nil alone is not "has a
// value" — {"SecretString":""} must not be imported as a real secret.
func TestReadSecret_EmptyStringValueIsSkipped(t *testing.T) {
	f := &fakeSM{
		pages:   [][]types.SecretListEntry{{{Name: aws.String("empty")}}},
		secrets: map[string]*secretsmanager.GetSecretValueOutput{"empty": {SecretString: aws.String("")}},
	}
	c := newClientWithFake(f)
	entries, skipped, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %+v, want none (empty value must not be imported)", entries)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0].Reason, "no value") {
		t.Fatalf("skipped = %+v, want one skip reasoning about no value", skipped)
	}
}

func TestReadSecret_BinaryValueIsSkippedNotImported(t *testing.T) {
	f := &fakeSM{
		pages:   [][]types.SecretListEntry{{{Name: aws.String("bin")}}},
		secrets: map[string]*secretsmanager.GetSecretValueOutput{"bin": {SecretBinary: []byte{0x01, 0x02, 0x03}}},
	}
	c := newClientWithFake(f)
	entries, skipped, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %+v, want none (binary secrets are skipped, not base64-imported)", entries)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0].Reason, "binary") {
		t.Fatalf("skipped = %+v, want one skip reasoning about a binary value", skipped)
	}
}

// TestList_DeletedSecretIsSkipped is the "deleted secret" case: a secret scheduled for deletion
// must be reported as skipped, never imported nor silently dropped from the report, and never
// even attempted via GetSecretValue.
func TestList_DeletedSecretIsSkipped(t *testing.T) {
	deletedAt := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	f := &fakeSM{
		pages: [][]types.SecretListEntry{{{Name: aws.String("gone"), DeletedDate: &deletedAt}}},
	}
	c := newClientWithFake(f)
	entries, skipped, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %+v, want none", entries)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0].Reason, "deletion") {
		t.Fatalf("skipped = %+v, want one skip mentioning deletion", skipped)
	}
	if len(f.getCalls) != 0 {
		t.Errorf("GetSecretValue was called for a deleted secret: %v", f.getCalls)
	}
}

func TestReadSecret_SplitJSONExplodesTopLevelKeys(t *testing.T) {
	f := &fakeSM{
		pages:   [][]types.SecretListEntry{{{Name: aws.String("creds")}}},
		secrets: map[string]*secretsmanager.GetSecretValueOutput{"creds": {SecretString: aws.String(`{"username":"alice","password":"hunter2"}`)}},
	}
	c := New(Config{SplitJSON: true})
	c.newClient = func(context.Context) (smAPI, error) { return f, nil }
	entries, skipped, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped = %+v, want none", skipped)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %+v, want 2 (one per JSON key)", entries)
	}
	got := map[string]string{}
	for _, e := range entries {
		got[e.Field] = e.Value
	}
	if got["username"] != "alice" || got["password"] != "hunter2" {
		t.Errorf("entries = %+v, want username=alice password=hunter2", got)
	}
}

func TestReadSecret_SplitJSONFalseImportsWholeValue(t *testing.T) {
	f := &fakeSM{
		pages:   [][]types.SecretListEntry{{{Name: aws.String("creds")}}},
		secrets: map[string]*secretsmanager.GetSecretValueOutput{"creds": {SecretString: aws.String(`{"username":"alice","password":"hunter2"}`)}},
	}
	c := newClientWithFake(f) // SplitJSON defaults to false
	entries, _, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].Field != "" || entries[0].Value != `{"username":"alice","password":"hunter2"}` {
		t.Fatalf("entries = %+v, want the whole JSON string as a single secret", entries)
	}
}

func TestReadSecret_SplitJSONOnNonObjectFallsBackToWholeValue(t *testing.T) {
	f := &fakeSM{
		pages:   [][]types.SecretListEntry{{{Name: aws.String("plain")}}},
		secrets: map[string]*secretsmanager.GetSecretValueOutput{"plain": {SecretString: aws.String("just-a-plain-value")}},
	}
	c := New(Config{SplitJSON: true})
	c.newClient = func(context.Context) (smAPI, error) { return f, nil }
	entries, _, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].Value != "just-a-plain-value" {
		t.Fatalf("entries = %+v, want the plain string imported whole", entries)
	}
}

// TestList_CanaryValueNeverLeaksIntoLocatorOrReason plants a distinctive marker as a real
// secret's value — including one exploded via --split-json — and asserts it appears only in
// Entry.Value/Entry.Field, never in Entry.Locator (built from the secret's NAME, never its
// value) or any Skipped.Reason (all static template strings, never interpolated from a value) —
// docs/design-keyorix-migrate.md's "Never log, print, or report a secret value". Unlike
// vaultsource (a self-hosted server this tool can be pointed at, and whose error bodies this
// design doc explicitly says are sanitized), an AWS API error is not tested here for echoing a
// secret value back: Secrets Manager's own API contract never echoes secret content into an
// error response, so asserting otherwise would encode a threat model this client cannot
// actually be exposed to.
func TestList_CanaryValueNeverLeaksIntoLocatorOrReason(t *testing.T) {
	const canary = "CANARY-do-not-leak-8f3a1c"
	f := &fakeSM{
		pages: [][]types.SecretListEntry{{
			{Name: aws.String("good")},
			{Name: aws.String("empty")},
			{Name: aws.String("split")},
		}},
		secrets: map[string]*secretsmanager.GetSecretValueOutput{
			"good":  {SecretString: aws.String(canary)},
			"empty": {SecretString: aws.String("")},
			"split": {SecretString: aws.String(`{"secret":"` + canary + `"}`)},
		},
	}
	c := New(Config{SplitJSON: true})
	c.newClient = func(context.Context) (smAPI, error) { return f, nil }
	entries, skipped, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	foundCanaryAsValue := false
	for _, e := range entries {
		if e.Value == canary {
			foundCanaryAsValue = true
		}
		if strings.Contains(e.Locator, canary) {
			t.Errorf("Entry.Locator leaked the canary value: %q", e.Locator)
		}
		if strings.Contains(e.Field, canary) {
			t.Errorf("Entry.Field leaked the canary value: %q", e.Field)
		}
	}
	if !foundCanaryAsValue {
		t.Fatal("no entry carried the canary as its Value — test setup is broken")
	}
	for _, s := range skipped {
		if strings.Contains(s.Reason, canary) {
			t.Errorf("Skipped.Reason leaked the canary value: %q", s.Reason)
		}
	}
}
