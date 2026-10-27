package services

// ERRLOSS-MFA-1: enforceProjectMFA classifies a GetProject failure by sentinel
// (storage.IsProjectNotFound), never by text. It used to return nil — no MFA
// check — for any lookup error whose message contained "not found", so a
// storage failure that merely said so let a session without a second factor
// into an MFA-required project. Driven through the real
// GetProjectRotationPlan RPC over faultstorage → LocalStorage. Each case also
// runs under ru; not t.Parallel(): the localizer is process-global.

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// errPMSLookalike reads like an absence but is a storage failure: it carries
// the words "not found" and is NOT storage.ErrProjectNotFound.
var errPMSLookalike = errors.New("failed to get project: replica 3: relation snapshot not found")

func pmsGRPCLocales(t *testing.T, fn func(t *testing.T, r *mfaAggregateTestRig)) {
	t.Helper()
	for _, lang := range []string{"en", "ru"} {
		t.Run(lang, func(t *testing.T) {
			r := newMFAAggregateTestRig(t) // (re)initializes i18n in en
			loc := i18n.GetLocalizer()
			loc.SetLanguage(lang)
			t.Cleanup(func() { loc.SetLanguage("en") })
			if lang == "ru" {
				require.NotContains(t, i18n.T("ErrorNotFound", nil), "not found",
					"the ru locale must not render ErrorNotFound in English, or this run proves nothing")
			}
			fn(t, r)
		})
	}
}

// TestEnforceProjectMFA_LookalikeNotFoundErrorDenies is the red-pre-fix case:
// pre-fix the RPC returned project 1's rotation plan to a session without MFA.
func TestEnforceProjectMFA_LookalikeNotFoundErrorDenies(t *testing.T) {
	pmsGRPCLocales(t, func(t *testing.T, r *mfaAggregateTestRig) {
		fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(r.db), &faultstorage.FaultSpec{
			Method: "GetProject", NthCall: 1, Kind: faultstorage.KindError, Err: errPMSLookalike,
		})
		svc := NewProjectService(core.NewKeyorixCore(fs))

		plan, err := svc.GetProjectRotationPlan(sessionCtx(1, "auditor", false, "secrets.read"), &pb.GetProjectRequest{Id: 1})
		require.True(t, fs.Fired(), "precondition: the MFA lookup must hit the injected fault")
		require.Error(t, err, "a storage error that only says \"not found\" must not skip the MFA gate")
		assert.Nil(t, plan)
		assert.Equal(t, codes.Internal, status.Code(err))
		assert.NotContains(t, status.Convert(err).Message(), "replica", "the storage error text must not reach the caller")
	})
}

// TestEnforceProjectMFA_MissingProjectPassesToRPCNotFound: a genuinely missing
// project is not an MFA question; the RPC's own NotFound answers.
func TestEnforceProjectMFA_MissingProjectPassesToRPCNotFound(t *testing.T) {
	pmsGRPCLocales(t, func(t *testing.T, r *mfaAggregateTestRig) {
		_, err := r.projSvc.GetProjectRotationPlan(sessionCtx(1, "auditor", false, "secrets.read"), &pb.GetProjectRequest{Id: 999})
		require.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err), "err: %v", err)

		_, err = r.projSvc.GetProjectRotationPlan(sessionCtx(1, "auditor", false, "secrets.read"), &pb.GetProjectRequest{Id: 1})
		assert.Equal(t, codes.PermissionDenied, status.Code(err), "control: the MFA-required project still denies a session without MFA")
	})
}
