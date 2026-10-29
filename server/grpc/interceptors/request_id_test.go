package interceptors

import (
	"context"
	"regexp"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/keyorixhq/keyorix/internal/logging"
)

var serverIDShape = regexp.MustCompile(`^[0-9a-f]{24}$`)

// docs/specs/audit-request-id.md: the id on an audit row is the server's, minted per
// call, and never a client-supplied value.
func TestRequestIDInterceptor_MintsPerCallAndIgnoresClientValue(t *testing.T) {
	icpt := RequestIDInterceptor()
	var seen []string
	handler := func(ctx context.Context, _ any) (any, error) {
		seen = append(seen, logging.ServerRequestID(ctx))
		if h := logging.HolderFrom(ctx); h != nil {
			if f := h.Snapshot(); f.ClientRequestID != "" {
				seen = append(seen, "client="+f.ClientRequestID)
			}
		}
		return nil, nil
	}

	in := metadata.NewIncomingContext(context.Background(), metadata.Pairs(RequestIDMetadataKey, "client-chosen-1"))
	for range 2 {
		if _, err := icpt(in, nil, &grpc.UnaryServerInfo{}, handler); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 4 {
		t.Fatalf("handler saw %v", seen)
	}
	first, second := seen[0], seen[2]
	for _, id := range []string{first, second} {
		if !serverIDShape.MatchString(id) {
			t.Errorf("server request id %q is not a minted 24-hex id", id)
		}
	}
	if first == second {
		t.Errorf("two calls shared the id %q", first)
	}
	if seen[1] != "client=client-chosen-1" || seen[3] != "client=client-chosen-1" {
		t.Errorf("the client's value should be kept only as the client_request_id log field: %v", seen)
	}
}

func TestRequestIDInterceptor_WithoutMetadataStillMints(t *testing.T) {
	var id string
	_, err := RequestIDInterceptor()(context.Background(), nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, _ any) (any, error) {
		id = logging.ServerRequestID(ctx)
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !serverIDShape.MatchString(id) {
		t.Fatalf("server request id %q is not a minted 24-hex id", id)
	}
}

type idTestStream struct {
	grpc.ServerStream
	ctx context.Context
	md  metadata.MD
}

func (s *idTestStream) Context() context.Context       { return s.ctx }
func (s *idTestStream) SetHeader(md metadata.MD) error { s.md = md; return nil }

func TestStreamRequestIDInterceptor_HandlerSeesTheIDAndHeaderCarriesIt(t *testing.T) {
	st := &idTestStream{ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs(RequestIDMetadataKey, "client-chosen-2"))}
	var id string
	err := StreamRequestIDInterceptor()(nil, st, &grpc.StreamServerInfo{}, func(_ any, s grpc.ServerStream) error {
		id = logging.ServerRequestID(s.Context())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !serverIDShape.MatchString(id) {
		t.Fatalf("stream server request id %q is not a minted 24-hex id", id)
	}
	if got := st.md.Get(RequestIDMetadataKey); len(got) != 1 || got[0] != id {
		t.Errorf("response header %v, want [%s]", got, id)
	}
}
