package rotation

import "fmt"

// CloudExecutorParams are the constructor parameters for a generate-upstream
// cloud rotation executor (aws-iam, gcp-service-account, azure-app). Region is
// used by aws-iam only; the others ignore it.
type CloudExecutorParams struct {
	Name        string
	Region      string
	AllowedRefs []string
}

type cloudExecutorCtor func(CloudExecutorParams) Executor

// cloudExecutors holds the generate-upstream cloud executors registered by the
// current build (ADR-109 step 6): aws-iam, gcp-service-account and azure-app
// each register themselves from an init() in their own file, guarded by that
// integration's //go:build !no<x> tag (and, for aws-iam, the pre-existing lean
// tag), so a no<x> build's binary never links the corresponding SDK.
var cloudExecutors = map[string]cloudExecutorCtor{}

// registerCloudExecutor panics on a duplicate kind — every registration
// happens from this package's own init()s, and a collision there is a
// build-time programming error, not a runtime condition to handle gracefully.
func registerCloudExecutor(kind string, ctor cloudExecutorCtor) {
	if _, exists := cloudExecutors[kind]; exists {
		panic(fmt.Sprintf("rotation: duplicate cloud executor registration for %q", kind))
	}
	cloudExecutors[kind] = ctor
}

// LookupCloudExecutor returns the generate-upstream rotation executor for kind
// ("aws-iam", "gcp-service-account" or "azure-app"), if the current build
// registers it. ok is false when the build excludes it (e.g. -tags noaws
// excludes "aws-iam") — callers that already switched on a literal kind
// string know at the call site that ok=false means exactly that, not "unknown
// kind" (an unrecognised kind never reaches this function).
func LookupCloudExecutor(kind string, params CloudExecutorParams) (Executor, bool) {
	ctor, found := cloudExecutors[kind]
	if !found {
		return nil, false
	}
	return ctor(params), true
}
