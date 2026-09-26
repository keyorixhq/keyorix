package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// resetShareFlags clears every package-level share flag var between tests, since
// cobra flag vars are shared globals across the whole test binary.
func resetShareFlags() {
	shareCreateSecretID, shareCreateRecipientID = 0, 0
	shareCreateIsGroup = false
	shareCreatePermission = "read"
	shareCreateExpires, shareCreateTTL = "", ""
	shareListSecretID = 0
	shareUpdateShareID = 0
	shareUpdatePermission = ""
	shareUpdateExpires, shareUpdateTTL = "", ""
	shareUpdateClearExpiry = false
	shareRevokeShareID = 0
	sharedSecretsUserID = 0
	groupSharesGroupID = 0
}

func TestResolveShareExpiry(t *testing.T) {
	t.Run("both empty is a permanent share", func(t *testing.T) {
		got, err := resolveShareExpiry("", "")
		if err != nil || got != nil {
			t.Fatalf("resolveShareExpiry(\"\", \"\") = %v, %v; want nil, nil", got, err)
		}
	})
	t.Run("both set is an error", func(t *testing.T) {
		if _, err := resolveShareExpiry("2026-07-01T15:00:00Z", "24h"); err == nil {
			t.Fatal("expected an error when both --expires and --ttl are set")
		}
	})
	t.Run("invalid RFC3339 is an error", func(t *testing.T) {
		if _, err := resolveShareExpiry("not-a-date", ""); err == nil {
			t.Fatal("expected an error for an invalid --expires value")
		}
	})
	t.Run("non-positive ttl is an error", func(t *testing.T) {
		if _, err := resolveShareExpiry("", "-1h"); err == nil {
			t.Fatal("expected an error for a non-positive --ttl")
		}
	})
	t.Run("valid ttl resolves relative to now", func(t *testing.T) {
		got, err := resolveShareExpiry("", "1h")
		if err != nil {
			t.Fatalf("resolveShareExpiry: %v", err)
		}
		if got == nil || got.Before(time.Now().Add(50*time.Minute)) {
			t.Fatalf("got %v, want roughly 1h from now", got)
		}
	})
}

func TestFormatShareExpiry(t *testing.T) {
	if got := formatShareExpiry(nil); got != "never" {
		t.Fatalf("formatShareExpiry(nil) = %q, want %q", got, "never")
	}
	tm := time.Date(2026, 7, 1, 15, 0, 0, 0, time.UTC)
	if got := formatShareExpiry(&tm); got != "2026-07-01 15:00:00" {
		t.Fatalf("formatShareExpiry = %q, want %q", got, "2026-07-01 15:00:00")
	}
}

func TestRunShareCreate_InvalidPermissionRejectedWithoutNetworkCall(t *testing.T) {
	resetShareFlags()
	defer resetShareFlags()
	shareCreateSecretID, shareCreateRecipientID = 1, 2
	shareCreatePermission = "admin"
	// No credentials configured -- if this reached the network call it would fail
	// on "no server configured", not on the permission check. It must not get there.
	if err := runShareCreate(shareCreateCmd, nil); err == nil {
		t.Fatal("expected an error for an invalid permission")
	}
}

func TestRunShareCreate_MutuallyExclusiveExpiryFlagsRejected(t *testing.T) {
	resetShareFlags()
	defer resetShareFlags()
	shareCreateSecretID, shareCreateRecipientID = 1, 2
	shareCreatePermission = "read"
	shareCreateExpires = "2026-07-01T15:00:00Z"
	shareCreateTTL = "24h"
	if err := runShareCreate(shareCreateCmd, nil); err == nil {
		t.Fatal("expected an error when both --expires and --ttl are set")
	}
}

func TestRunShareUpdate_ClearExpiryCombinedWithExpiresRejected(t *testing.T) {
	resetShareFlags()
	defer resetShareFlags()
	shareUpdateShareID = 1
	shareUpdatePermission = "write"
	shareUpdateClearExpiry = true
	shareUpdateExpires = "2026-07-01T15:00:00Z"
	if err := runShareUpdate(shareUpdateCmd, nil); err == nil {
		t.Fatal("expected an error when --clear-expiry is combined with --expires")
	}
}

func TestRunShareUpdate_InvalidPermissionRejected(t *testing.T) {
	resetShareFlags()
	defer resetShareFlags()
	shareUpdateShareID = 1
	shareUpdatePermission = "admin"
	if err := runShareUpdate(shareUpdateCmd, nil); err == nil {
		t.Fatal("expected an error for an invalid permission")
	}
}

func TestRunShareSelfRemove_InvalidSecretIDArgRejected(t *testing.T) {
	if err := runShareSelfRemove(shareSelfRemoveCmd, []string{"not-a-number"}); err == nil {
		t.Fatal("expected an error for a non-numeric secret ID argument")
	}
}

// TestRunShareCreate_MatchesOldCLIRemoteOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 9): the field labels and values must match the
// old CLI's remote-mode `share create` output byte-for-byte for the same server
// response (internal/cli/share/remote.go's runCreateRemote).
func TestRunShareCreate_MatchesOldCLIRemoteOutputShape(t *testing.T) {
	resetShareFlags()
	defer resetShareFlags()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/secrets/5/share" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprint(w, `{"data":{"ID":42,"SecretID":5,"OwnerID":1,"RecipientID":9,"IsGroup":false,"Permission":"read","CreatedAt":"2026-01-02T00:00:00Z","ExpiresAt":null}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	shareCreateSecretID, shareCreateRecipientID = 5, 9
	shareCreatePermission = "read"

	out := captureStdout(t, func() {
		if err := runShareCreate(shareCreateCmd, nil); err != nil {
			t.Fatalf("runShareCreate: %v", err)
		}
	})

	if !containsAll(out, "Secret shared successfully",
		"Share ID: 42", "Secret ID: 5", "Owner ID: 1", "Recipient ID: 9",
		"Is Group: false", "Permission: read", "Created At: 2026-01-02", "Expires At: never") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunShareList_EmptyPrintsOldCLIMessage(t *testing.T) {
	resetShareFlags()
	defer resetShareFlags()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"shares":[]}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	shareListSecretID = 5

	out := captureStdout(t, func() {
		if err := runShareList(shareListCmd, nil); err != nil {
			t.Fatalf("runShareList: %v", err)
		}
	})
	if out != "No shares found for this secret.\n" {
		t.Fatalf("output = %q, want the old CLI's exact empty-state message", out)
	}
}

func TestRunShareList_MatchesOldCLIRemoteOutputShape(t *testing.T) {
	resetShareFlags()
	defer resetShareFlags()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"shares":[{"ID":42,"SecretID":5,"OwnerID":1,"RecipientID":9,"IsGroup":false,"Permission":"write","CreatedAt":"2026-01-02T00:00:00Z","ExpiresAt":"2026-07-01T15:00:00Z"}]}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	shareListSecretID = 5

	out := captureStdout(t, func() {
		if err := runShareList(shareListCmd, nil); err != nil {
			t.Fatalf("runShareList: %v", err)
		}
	})
	if !containsAll(out, "ID", "SECRET ID", "OWNER ID", "RECIPIENT ID", "IS GROUP", "PERMISSION", "CREATED AT", "EXPIRES AT") {
		t.Fatalf("header row missing expected columns, got: %q", out)
	}
	if !containsAll(out, "42", "5", "1", "9", "false", "write", "2026-01-02", "2026-07-01") {
		t.Fatalf("row missing expected fields, got: %q", out)
	}
}

// TestRunShareUpdate_PrintsAllEightFields closes the documented output-parity gap
// (docs/cli-split-inventory.md §8): the old CLI's remote branch printed only 4 of the
// 8 fields the embedded branch and `share create` print. This port prints all 8.
func TestRunShareUpdate_PrintsAllEightFields(t *testing.T) {
	resetShareFlags()
	defer resetShareFlags()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/shares/42" || r.Method != http.MethodPut {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"ID":42,"SecretID":5,"OwnerID":1,"RecipientID":9,"IsGroup":true,"Permission":"write","UpdatedAt":"2026-01-03T00:00:00Z","ExpiresAt":null}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	shareUpdateShareID = 42
	shareUpdatePermission = "write"

	out := captureStdout(t, func() {
		if err := runShareUpdate(shareUpdateCmd, nil); err != nil {
			t.Fatalf("runShareUpdate: %v", err)
		}
	})

	if !containsAll(out, "Share permission updated successfully",
		"Share ID: 42", "Secret ID: 5", "Owner ID: 1", "Recipient ID: 9",
		"Is Group: true", "Permission: write", "Updated At: 2026-01-03", "Expires At: never") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunShareRevoke_MatchesOldCLIRemoteOutputShape(t *testing.T) {
	resetShareFlags()
	defer resetShareFlags()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/shares/42" || r.Method != http.MethodDelete {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	shareRevokeShareID = 42

	out := captureStdout(t, func() {
		if err := runShareRevoke(shareRevokeCmd, nil); err != nil {
			t.Fatalf("runShareRevoke: %v", err)
		}
	})
	if out != "Share revoked successfully!\nShare ID: 42\n" {
		t.Fatalf("output = %q, want the old CLI's exact revoke message", out)
	}
}

func TestRunShareSelfRemove_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/secrets/5/self-share" || r.Method != http.MethodDelete {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runShareSelfRemove(shareSelfRemoveCmd, []string{"5"}); err != nil {
			t.Fatalf("runShareSelfRemove: %v", err)
		}
	})
	if out != "Removed yourself from secret 5.\n" {
		t.Fatalf("output = %q, want the old CLI's exact self-remove message", out)
	}
}

func TestRunSharedSecrets_DefaultsToCallerScopedRoute(t *testing.T) {
	resetShareFlags()
	defer resetShareFlags()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/shared-secrets" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"secrets":[{"id":3,"name":"db-pass","type":"password","project_id":1,"environment_id":2,"created_by":"alice","created_at":"2026-01-02T00:00:00Z"}]}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runSharedSecrets(sharedSecretsCmd, nil); err != nil {
			t.Fatalf("runSharedSecrets: %v", err)
		}
	})
	if !containsAll(out, "ID", "NAME", "TYPE", "PROJECT", "ENVIRONMENT", "CREATED BY", "CREATED AT") {
		t.Fatalf("header row missing expected columns, got: %q", out)
	}
	if !containsAll(out, "3", "db-pass", "password", "1", "2", "alice", "2026-01-02") {
		t.Fatalf("row missing expected fields, got: %q", out)
	}
}

func TestRunSharedSecrets_NonZeroUserIDUsesAdminScopedRoute(t *testing.T) {
	resetShareFlags()
	defer resetShareFlags()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users/7/shared-secrets" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"secrets":[]}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	sharedSecretsUserID = 7

	out := captureStdout(t, func() {
		if err := runSharedSecrets(sharedSecretsCmd, nil); err != nil {
			t.Fatalf("runSharedSecrets: %v", err)
		}
	})
	if out != "No shared secrets found.\n" {
		t.Fatalf("output = %q, want the old CLI's exact empty-state message", out)
	}
}

func TestRunGroupShares_MatchesOldCLIRemoteOutputShape(t *testing.T) {
	resetShareFlags()
	defer resetShareFlags()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/groups/3/shares" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"shares":[{"ID":42,"SecretID":5,"OwnerID":1,"RecipientID":3,"Permission":"read","CreatedAt":"2026-01-02T00:00:00Z"}]}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	groupSharesGroupID = 3

	out := captureStdout(t, func() {
		if err := runGroupShares(groupSharesCmd, nil); err != nil {
			t.Fatalf("runGroupShares: %v", err)
		}
	})
	if !containsAll(out, "ID", "SECRET ID", "OWNER ID", "GROUP ID", "PERMISSION", "CREATED AT") {
		t.Fatalf("header row missing expected columns, got: %q", out)
	}
	if !containsAll(out, "42", "5", "1", "3", "read", "2026-01-02") {
		t.Fatalf("row missing expected fields, got: %q", out)
	}
}

// resetFlagChanged clears the .Changed bit every flag in cmd's FlagSet carries after a
// ParseFlags call -- required, since these *cobra.Command values are package-level
// singletons shared across the whole test binary: pflag.FlagSet.Parse only ever sets
// Changed to true, it never clears it back to false for a flag absent from a later
// call, so a later ParseFlags([]string{}) in the SAME test (or a later test, if run in
// the same process) would otherwise still see the flag as "provided" from an earlier
// call and ValidateRequiredFlags would never see the missing-flag case at all.
func resetFlagChanged(cmd *cobra.Command) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) { f.Changed = false })
}

// TestShareListCmd_RequiredFlags exercises the actual cobra flag-parsing/validation
// machinery `shareListCmd.MarkFlagRequired("secret-id")` (share.go init()) wires up --
// every other test in this file calls runShareList directly with package vars set by
// hand, which never touches MarkFlagRequired's enforcement at all (Flag.Changed is only
// ever set by real flag parsing). ParseFlags is cobra's own flag-parsing entry point, so
// this is what `keyorix share list` run from an actual shell without --secret-id hits.
func TestShareListCmd_RequiredFlags(t *testing.T) {
	resetShareFlags()
	defer resetShareFlags()
	defer resetFlagChanged(shareListCmd)

	if err := shareListCmd.ParseFlags(nil); err != nil {
		t.Fatalf("ParseFlags(nil): %v", err)
	}
	if err := shareListCmd.ValidateRequiredFlags(); err == nil {
		t.Fatal("expected an error when --secret-id is not provided")
	}

	resetFlagChanged(shareListCmd)
	if err := shareListCmd.ParseFlags([]string{"--secret-id", "5"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if err := shareListCmd.ValidateRequiredFlags(); err != nil {
		t.Fatalf("unexpected error with --secret-id provided: %v", err)
	}
}

// TestShareUpdateCmd_RequiredFlags covers both of shareUpdateCmd's required flags
// (--share-id, --permission): missing either one must be caught, and only providing
// both must clear the check -- see TestShareListCmd_RequiredFlags for why this can't be
// exercised by calling runShareUpdate directly.
func TestShareUpdateCmd_RequiredFlags(t *testing.T) {
	resetShareFlags()
	defer resetShareFlags()
	defer resetFlagChanged(shareUpdateCmd)

	if err := shareUpdateCmd.ParseFlags(nil); err != nil {
		t.Fatalf("ParseFlags(nil): %v", err)
	}
	if err := shareUpdateCmd.ValidateRequiredFlags(); err == nil {
		t.Fatal("expected an error when neither --share-id nor --permission is provided")
	}

	resetFlagChanged(shareUpdateCmd)
	if err := shareUpdateCmd.ParseFlags([]string{"--share-id", "42"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if err := shareUpdateCmd.ValidateRequiredFlags(); err == nil {
		t.Fatal("expected an error when --permission is still missing")
	}

	resetFlagChanged(shareUpdateCmd)
	if err := shareUpdateCmd.ParseFlags([]string{"--share-id", "42", "--permission", "read"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if err := shareUpdateCmd.ValidateRequiredFlags(); err != nil {
		t.Fatalf("unexpected error with both required flags provided: %v", err)
	}
}

// TestShareRevokeCmd_RequiredFlags is the revoke-side counterpart of
// TestShareListCmd_RequiredFlags for --share-id.
func TestShareRevokeCmd_RequiredFlags(t *testing.T) {
	resetShareFlags()
	defer resetShareFlags()
	defer resetFlagChanged(shareRevokeCmd)

	if err := shareRevokeCmd.ParseFlags(nil); err != nil {
		t.Fatalf("ParseFlags(nil): %v", err)
	}
	if err := shareRevokeCmd.ValidateRequiredFlags(); err == nil {
		t.Fatal("expected an error when --share-id is not provided")
	}

	resetFlagChanged(shareRevokeCmd)
	if err := shareRevokeCmd.ParseFlags([]string{"--share-id", "42"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if err := shareRevokeCmd.ValidateRequiredFlags(); err != nil {
		t.Fatalf("unexpected error with --share-id provided: %v", err)
	}
}

// TestGroupSharesCmd_RequiredFlags is the group-shares counterpart for --group-id.
func TestGroupSharesCmd_RequiredFlags(t *testing.T) {
	resetShareFlags()
	defer resetShareFlags()
	defer resetFlagChanged(groupSharesCmd)

	if err := groupSharesCmd.ParseFlags(nil); err != nil {
		t.Fatalf("ParseFlags(nil): %v", err)
	}
	if err := groupSharesCmd.ValidateRequiredFlags(); err == nil {
		t.Fatal("expected an error when --group-id is not provided")
	}

	resetFlagChanged(groupSharesCmd)
	if err := groupSharesCmd.ParseFlags([]string{"--group-id", "3"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if err := groupSharesCmd.ValidateRequiredFlags(); err != nil {
		t.Fatalf("unexpected error with --group-id provided: %v", err)
	}
}

func TestRunGroupShares_EmptyPrintsOldCLIMessage(t *testing.T) {
	resetShareFlags()
	defer resetShareFlags()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"shares":[]}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	groupSharesGroupID = 3

	out := captureStdout(t, func() {
		if err := runGroupShares(groupSharesCmd, nil); err != nil {
			t.Fatalf("runGroupShares: %v", err)
		}
	})
	if out != "No shares found for this group.\n" {
		t.Fatalf("output = %q, want the old CLI's exact empty-state message", out)
	}
}
