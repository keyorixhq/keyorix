package services

// CORE-ERR-FAMILY-7 item 5: a core storage read fault (core.ErrStorageReadUnavailable)
// renders as a fixed sentence; its driver cause is only in the Unwrap chain. A gRPC
// service that logs such an error with %v writes "storage temporarily unavailable,
// please retry" and the operator never sees why. #4077 fixed the REST side with
// core.StorageReadFaultDetail; these tests sweep every storage call of an RPC with an
// injected fault and require that no log line carries the fixed sentence without the
// injected cause.

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// lostFaultCauses faults each storage call of call() in turn (each call site up to its
// 3rd invocation) and returns one line per fault whose driver cause the operator log
// lost: a log line that says the storage fault's fixed sentence without the injected
// cause, or an RPC that answered Internal or Unavailable with no log line naming the
// cause at all. call runs once clean first to learn its calls.
func lostFaultCauses(t *testing.T, faulty *faultstorage.FaultyStorage, call func() error) []string {
	t.Helper()
	faulty.Arm(nil)
	before := len(faulty.Calls())
	_ = call()
	counts := map[string]int{}
	var order []string
	for _, c := range faulty.Calls()[before:] {
		if counts[c.Method] == 0 {
			order = append(order, c.Method)
		}
		counts[c.Method]++
	}
	require.NotEmpty(t, order, "the RPC made no storage call")

	var lost []string
	prev := log.Writer()
	t.Cleanup(func() { log.SetOutput(prev) })
	for _, m := range order {
		for nth := 1; nth <= min(counts[m], 3); nth++ {
			cause := fmt.Sprintf("injected-cause-%s-%d", m, nth)
			var buf bytes.Buffer
			log.SetOutput(&buf)
			faulty.Arm(&faultstorage.FaultSpec{Method: m, NthCall: nth, Kind: faultstorage.KindError, Err: fmt.Errorf("pq: %s", cause)})
			err := call()
			faulty.Arm(nil)
			log.SetOutput(prev)
			logged := strings.Contains(buf.String(), cause)
			for line := range strings.SplitSeq(buf.String(), "\n") {
				if strings.Contains(line, core.StorageReadUnavailableMessage) && !strings.Contains(line, cause) {
					lost = append(lost, fmt.Sprintf("%s#%d logged without its cause: %s", m, nth, line))
				}
			}
			if code := status.Code(err); (code == codes.Internal || code == codes.Unavailable) && !logged {
				lost = append(lost, fmt.Sprintf("%s#%d answered %s and logged no cause", m, nth, code))
			}
		}
	}
	return lost
}

// errFamily7FaultWorld is a seeded RBAC world (user 1 global admin, user 2 a target, one
// group) whose core reads through a FaultyStorage.
func errFamily7FaultWorld(t *testing.T) (*faultstorage.FaultyStorage, *core.KeyorixCore, *models.Group) {
	t.Helper()
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.AssignUserRole(t, 1, 1, nil)
	h.CreateTestUser(t, "target", 2)
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(h.DB), nil)
	cs := core.NewKeyorixCore(faulty)
	grp, err := cs.CreateGroup(errFamily7Ctx(), 1, &core.CreateGroupRequest{Name: "ef7-group"})
	require.NoError(t, err)
	return faulty, cs, grp
}

func errFamily7Ctx() context.Context {
	return authCtx(1, "admin", "users.read", "users.write", "secrets.read", "secrets.write", "roles.assign")
}

func TestErrFamily7_UserServiceLogsTheStorageFaultCause(t *testing.T) {
	faulty, cs, _ := errFamily7FaultWorld(t)
	users := NewUserService(cs)
	ctx := errFamily7Ctx()
	require.Empty(t, lostFaultCauses(t, faulty, func() error {
		_, err := users.UpdateUser(ctx, &pb.UpdateUserRequest{Id: 2, DisplayName: new("x")})
		return err
	}), "UpdateUser")
	require.Empty(t, lostFaultCauses(t, faulty, func() error {
		_, err := users.ReissueOneTimePassword(ctx, &pb.ReissueOneTimePasswordRequest{Id: 2})
		return err
	}), "ReissueOneTimePassword")
}

func TestErrFamily7_ShareServiceLogsTheStorageFaultCause(t *testing.T) {
	faulty, cs, _ := errFamily7FaultWorld(t)
	shares := NewShareService(cs)
	ctx := errFamily7Ctx()
	require.Empty(t, lostFaultCauses(t, faulty, func() error {
		_, err := shares.ListUserShares(ctx, &pb.ListUserSharesRequest{})
		return err
	}), "ListUserShares")
}

func TestErrFamily7_ProjectServiceLogsTheStorageFaultCause(t *testing.T) {
	faulty, cs, _ := errFamily7FaultWorld(t)
	projects := NewProjectService(cs)
	ctx := errFamily7Ctx()
	require.Empty(t, lostFaultCauses(t, faulty, func() error {
		_, err := projects.GetProject(ctx, &pb.GetProjectRequest{Id: 1})
		return err
	}), "GetProject")
	require.Empty(t, lostFaultCauses(t, faulty, func() error {
		_, err := projects.ListProjects(ctx, &emptypb.Empty{})
		return err
	}), "ListProjects")
}

func TestErrFamily7_GroupServiceLogsTheStorageFaultCause(t *testing.T) {
	faulty, cs, grp := errFamily7FaultWorld(t)
	groups := NewGroupService(cs)
	ctx := errFamily7Ctx()
	require.Empty(t, lostFaultCauses(t, faulty, func() error {
		_, err := groups.GetGroup(ctx, &pb.GetGroupRequest{Id: uint32(grp.ID)})
		return err
	}), "GetGroup")
}
