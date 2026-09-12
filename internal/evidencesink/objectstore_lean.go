//go:build lean

// objectstore_lean.go — lean-build stand-in for objectstore.go. Keeps the same
// exported surface (NewObjectStore, ObjectStore.ForwardEvidence/Target, and
// shares ObjectStoreConfig from objectstore_config.go) so server/main.go's
// unconditional `evidencesink.NewObjectStore` call compiles either way, but
// drops the aws-sdk-go-v2/service/s3 import entirely. A config that still
// enables the object-store evidence target fails LOUDLY at server startup
// with a clear "not built into this binary" error — server/main.go treats a
// non-nil error from NewObjectStore as fatal — never a silent no-op, so an
// operator who deploys the lean binary against a config written for the full
// one finds out at startup, not the first time a scheduled evidence export
// silently fails to reach the bucket.
package evidencesink

import (
	"context"
	"fmt"
)

// ObjectStore is the lean-build stand-in for the real sink in objectstore.go.
type ObjectStore struct{}

// leanObjectStoreErr is returned by every ObjectStore method in a lean build.
func leanObjectStoreErr() error {
	return fmt.Errorf("evidencesink: object-store target not available in this lean build (compiled with -tags lean); rebuild without the lean tag to use it")
}

// NewObjectStore returns an error unconditionally in a lean build: there is no
// working S3 client behind it, and returning a non-nil error (rather than a
// usable-looking stub) is what makes server/main.go fail startup instead of
// silently accepting a config it cannot honor.
func NewObjectStore(_ context.Context, _ ObjectStoreConfig) (*ObjectStore, error) {
	return nil, leanObjectStoreErr()
}

func (o *ObjectStore) ForwardEvidence(_ context.Context, _ string, _ []byte, _ string) error {
	return leanObjectStoreErr()
}

func (o *ObjectStore) Target() string { return "objectstore:unavailable-in-lean-build" }
