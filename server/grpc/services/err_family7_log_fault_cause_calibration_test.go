package services

// The calibration of lostFaultCauses (err_family7_log_fault_cause_test.go), in its own
// file because it uses internalFailure, so the per-service tests can be red-proven
// against a tree without it.

import (
	"log"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The sweep is not vacuous: an error mapper that answers Internal and logs nothing is
// reported, and one that logs the fault's fixed sentence without its cause too.
func TestErrFamily7_LostFaultCauseSweepCalibration(t *testing.T) {
	faulty, cs, _ := errFamily7FaultWorld(t)
	silent := func() error {
		if _, err := cs.GetProject(errFamily7Ctx(), 1); err != nil {
			return status.Error(codes.Internal, "project operation failed")
		}
		return nil
	}
	require.NotEmpty(t, lostFaultCauses(t, faulty, silent), "a silent Internal must be reported")
	fixedSentenceOnly := func() error {
		if _, err := cs.GetProject(errFamily7Ctx(), 1); err != nil {
			log.Printf("get project: %v", err)
			return status.Error(codes.Internal, "project operation failed")
		}
		return nil
	}
	require.NotEmpty(t, lostFaultCauses(t, faulty, fixedSentenceOnly), "a %v of a typed fault must be reported")
	withCause := func() error {
		if _, err := cs.GetProject(errFamily7Ctx(), 1); err != nil {
			return internalFailure("project operation failed", err)
		}
		return nil
	}
	require.Empty(t, lostFaultCauses(t, faulty, withCause), "internalFailure keeps the cause")
}
