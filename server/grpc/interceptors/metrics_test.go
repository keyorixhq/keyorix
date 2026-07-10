package interceptors

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
)

// TestMetricsInterceptor_CountsSuccessAndError verifies that the metrics interceptor
// correctly increments success and error counters, and records total duration.
func TestMetricsInterceptor_CountsSuccessAndError(t *testing.T) {
	// Reset global metrics before the test to avoid interference from other tests.
	// The global is a package-level var; we snapshot it and compare deltas.
	before := GetGRPCMetrics()

	interceptor := MetricsInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}

	// A successful call.
	_, err := interceptor(context.Background(), nil, info,
		func(_ context.Context, _ interface{}) (interface{}, error) {
			return "ok", nil
		})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// A failing call.
	_, err = interceptor(context.Background(), nil, info,
		func(_ context.Context, _ interface{}) (interface{}, error) {
			return nil, errors.New("fail")
		})
	if err == nil {
		t.Fatal("expected an error from the interceptor, got nil")
	}

	after := GetGRPCMetrics()
	deltaTotal := after.TotalRequests - before.TotalRequests
	deltaSuccess := after.SuccessRequests - before.SuccessRequests
	deltaError := after.ErrorRequests - before.ErrorRequests

	if deltaTotal != 2 {
		t.Errorf("TotalRequests delta = %d, want 2", deltaTotal)
	}
	if deltaSuccess != 1 {
		t.Errorf("SuccessRequests delta = %d, want 1", deltaSuccess)
	}
	if deltaError != 1 {
		t.Errorf("ErrorRequests delta = %d, want 1", deltaError)
	}
	if after.TotalDuration <= before.TotalDuration {
		t.Errorf("TotalDuration should have increased: before=%d, after=%d", before.TotalDuration, after.TotalDuration)
	}
}

// TestMetrics_AverageResponseTime verifies the helper returns 0 when no requests have
// been recorded.
func TestMetrics_AverageResponseTime(t *testing.T) {
	m := &Metrics{}
	if got := m.GetAverageResponseTime(); got != 0 {
		t.Errorf("GetAverageResponseTime on empty Metrics = %v, want 0", got)
	}
}

// TestMetrics_SuccessAndErrorRateOnEmpty verifies helper functions return 0 for an empty
// Metrics struct (no division by zero).
func TestMetrics_SuccessAndErrorRateOnEmpty(t *testing.T) {
	m := &Metrics{}
	if got := m.GetSuccessRate(); got != 0 {
		t.Errorf("GetSuccessRate on empty Metrics = %v, want 0", got)
	}
	if got := m.GetErrorRate(); got != 0 {
		t.Errorf("GetErrorRate on empty Metrics = %v, want 0", got)
	}
}

// TestMetrics_Rates verifies computed rates for a known distribution.
func TestMetrics_Rates(t *testing.T) {
	m := &Metrics{
		TotalRequests:   10,
		SuccessRequests: 8,
		ErrorRequests:   2,
		TotalDuration:   int64(10e9), // 10 seconds total → 1000ms avg
	}
	if got := m.GetSuccessRate(); got != 80.0 {
		t.Errorf("GetSuccessRate = %v, want 80", got)
	}
	if got := m.GetErrorRate(); got != 20.0 {
		t.Errorf("GetErrorRate = %v, want 20", got)
	}
	if got := m.GetAverageResponseTime(); got != 1000.0 {
		t.Errorf("GetAverageResponseTime = %v, want 1000", got)
	}
}
