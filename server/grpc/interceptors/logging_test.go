package interceptors

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
)

// TestLoggingInterceptor_SuccessPath ensures the logging interceptor passes through
// the handler's result without modifying it on a successful call.
func TestLoggingInterceptor_SuccessPath(t *testing.T) {
	interceptor := LoggingInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}

	resp, err := interceptor(context.Background(), "req", info,
		func(_ context.Context, req interface{}) (interface{}, error) {
			return "resp-value", nil
		})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp != "resp-value" {
		t.Fatalf("expected resp-value, got %v", resp)
	}
}

// TestLoggingInterceptor_ErrorPath ensures the logging interceptor propagates handler
// errors without swallowing them.
func TestLoggingInterceptor_ErrorPath(t *testing.T) {
	interceptor := LoggingInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}
	handlerErr := errors.New("something went wrong")

	resp, err := interceptor(context.Background(), nil, info,
		func(_ context.Context, _ interface{}) (interface{}, error) {
			return nil, handlerErr
		})
	if err == nil {
		t.Fatal("expected an error from the interceptor, got nil")
	}
	if !errors.Is(err, handlerErr) {
		t.Fatalf("expected the original error to propagate, got %v", err)
	}
	if resp != nil {
		t.Fatalf("expected nil response on error, got %v", resp)
	}
}

// TestGetErrorMessage verifies the helper returns the error string or empty for nil.
func TestGetErrorMessage(t *testing.T) {
	if got := getErrorMessage(nil); got != "" {
		t.Errorf("getErrorMessage(nil) = %q, want empty string", got)
	}
	e := errors.New("test error")
	if got := getErrorMessage(e); got != e.Error() {
		t.Errorf("getErrorMessage(err) = %q, want %q", got, e.Error())
	}
}
