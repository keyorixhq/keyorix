package azuresource

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// fakeAz is an in-process azAPI fake — no network, no real Key Vault. pages splits the secret
// list into successive pages (via runtime.NewPager, the SDK's own real pager type, fed
// in-memory) to exercise pagination without HTTP.
type fakeAz struct {
	pages    [][]*azsecrets.SecretProperties
	secrets  map[string]azsecrets.GetSecretResponse
	getErr   map[string]error
	getCalls []string
}

func (f *fakeAz) NewListSecretPropertiesPager(_ *azsecrets.ListSecretPropertiesOptions) *runtime.Pager[azsecrets.ListSecretPropertiesResponse] {
	idx := 0
	return runtime.NewPager(runtime.PagingHandler[azsecrets.ListSecretPropertiesResponse]{
		More: func(azsecrets.ListSecretPropertiesResponse) bool { return idx < len(f.pages) },
		Fetcher: func(_ context.Context, _ *azsecrets.ListSecretPropertiesResponse) (azsecrets.ListSecretPropertiesResponse, error) {
			page := f.pages[idx]
			idx++
			return azsecrets.ListSecretPropertiesResponse{
				SecretPropertiesListResult: azsecrets.SecretPropertiesListResult{Value: page},
			}, nil
		},
	})
}

func (f *fakeAz) GetSecret(_ context.Context, name, _ string, _ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	f.getCalls = append(f.getCalls, name)
	if err, ok := f.getErr[name]; ok {
		return azsecrets.GetSecretResponse{}, err
	}
	if out, ok := f.secrets[name]; ok {
		return out, nil
	}
	return azsecrets.GetSecretResponse{}, errors.New("fakeAz: no such secret")
}

func idProp(name string) *azsecrets.ID {
	id := azsecrets.ID("https://fake.vault.azure.net/secrets/" + name)
	return &id
}

func enabled(v bool) *azsecrets.SecretAttributes { return &azsecrets.SecretAttributes{Enabled: &v} }

func newClientWithFake(f *fakeAz) *Client {
	c := New(Config{VaultURL: "https://fake.vault.azure.net/"})
	c.newClient = func(context.Context) (azAPI, error) { return f, nil }
	return c
}

func strPtr(s string) *string { return &s }

func TestList_PaginatesAcrossMultiplePages(t *testing.T) {
	f := &fakeAz{
		pages: [][]*azsecrets.SecretProperties{
			{{ID: idProp("s1"), Attributes: enabled(true)}},
			{{ID: idProp("s2"), Attributes: enabled(true)}},
		},
		secrets: map[string]azsecrets.GetSecretResponse{
			"s1": {Secret: azsecrets.Secret{Value: strPtr("v1")}},
			"s2": {Secret: azsecrets.Secret{Value: strPtr("v2")}},
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
	if len(entries) != 2 {
		t.Fatalf("entries = %+v, want 2", entries)
	}
}

func TestList_NamePrefixFilters(t *testing.T) {
	f := &fakeAz{
		pages: [][]*azsecrets.SecretProperties{{
			{ID: idProp("team-a-db"), Attributes: enabled(true)},
			{ID: idProp("team-b-db"), Attributes: enabled(true)},
		}},
		secrets: map[string]azsecrets.GetSecretResponse{
			"team-a-db": {Secret: azsecrets.Secret{Value: strPtr("v1")}},
			"team-b-db": {Secret: azsecrets.Secret{Value: strPtr("v2")}},
		},
	}
	c := New(Config{VaultURL: "https://fake.vault.azure.net/", NamePrefix: "team-a"})
	c.newClient = func(context.Context) (azAPI, error) { return f, nil }
	entries, _, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].RawName != "team-a-db" {
		t.Fatalf("entries = %+v, want only team-a-db", entries)
	}
	if len(f.getCalls) != 1 {
		t.Errorf("GetSecret called for %v, want only the matching secret fetched", f.getCalls)
	}
}

// TestList_DisabledSecretIsSkipped is the "disabled secret" case: a secret whose current
// version is disabled must be reported as skipped, and GetSecret must never even be called for
// it (Key Vault's data-plane GetSecret would still happily return a disabled secret's value —
// the enabled check has to happen from the listed properties, not be inferred from a read
// failure that will never occur).
func TestList_DisabledSecretIsSkipped(t *testing.T) {
	f := &fakeAz{
		pages: [][]*azsecrets.SecretProperties{{{ID: idProp("off"), Attributes: enabled(false)}}},
	}
	c := newClientWithFake(f)
	entries, skipped, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %+v, want none", entries)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0].Reason, "disabled") {
		t.Fatalf("skipped = %+v, want one skip mentioning disabled", skipped)
	}
	if len(f.getCalls) != 0 {
		t.Errorf("GetSecret was called for a disabled secret: %v", f.getCalls)
	}
}

// TestReadSecret_EmptyStringValueIsSkipped locks in the same bug class
// internal/connect/azurekv.go's GetSecret was fixed for: Value != nil alone is not "has a
// value" — {"value":""} must not be imported as a real secret.
func TestReadSecret_EmptyStringValueIsSkipped(t *testing.T) {
	f := &fakeAz{
		pages:   [][]*azsecrets.SecretProperties{{{ID: idProp("empty"), Attributes: enabled(true)}}},
		secrets: map[string]azsecrets.GetSecretResponse{"empty": {Secret: azsecrets.Secret{Value: strPtr("")}}},
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

func TestReadSecret_SplitJSONExplodesTopLevelKeys(t *testing.T) {
	f := &fakeAz{
		pages: [][]*azsecrets.SecretProperties{{{ID: idProp("creds"), Attributes: enabled(true)}}},
		secrets: map[string]azsecrets.GetSecretResponse{
			"creds": {Secret: azsecrets.Secret{Value: strPtr(`{"username":"alice","password":"hunter2"}`)}},
		},
	}
	c := New(Config{VaultURL: "https://fake.vault.azure.net/", SplitJSON: true})
	c.newClient = func(context.Context) (azAPI, error) { return f, nil }
	entries, _, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
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

// TestList_CanaryValueNeverLeaksIntoLocatorOrReason mirrors awssource's canary test: a
// distinctive marker used as a secret value (including a split-json field) must never appear in
// a Locator (built only from the secret name) or a Skipped.Reason (static template strings).
func TestList_CanaryValueNeverLeaksIntoLocatorOrReason(t *testing.T) {
	const canary = "CANARY-do-not-leak-8f3a1c"
	f := &fakeAz{
		pages: [][]*azsecrets.SecretProperties{{
			{ID: idProp("good"), Attributes: enabled(true)},
			{ID: idProp("off"), Attributes: enabled(false)},
			{ID: idProp("split"), Attributes: enabled(true)},
		}},
		secrets: map[string]azsecrets.GetSecretResponse{
			"good":  {Secret: azsecrets.Secret{Value: strPtr(canary)}},
			"split": {Secret: azsecrets.Secret{Value: strPtr(`{"secret":"` + canary + `"}`)}},
		},
	}
	c := New(Config{VaultURL: "https://fake.vault.azure.net/", SplitJSON: true})
	c.newClient = func(context.Context) (azAPI, error) { return f, nil }
	entries, skipped, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	foundCanary := false
	for _, e := range entries {
		if e.Value == canary {
			foundCanary = true
		}
		if strings.Contains(e.Locator, canary) || strings.Contains(e.Field, canary) {
			t.Errorf("Entry leaked the canary value outside its Value field: %+v", e)
		}
	}
	if !foundCanary {
		t.Fatal("no entry carried the canary as its Value — test setup is broken")
	}
	for _, s := range skipped {
		if strings.Contains(s.Reason, canary) {
			t.Errorf("Skipped.Reason leaked the canary value: %q", s.Reason)
		}
	}
}
