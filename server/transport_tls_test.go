package main

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

func cfgWith(httpEnabled, httpTLS, grpcEnabled, grpcTLS, require bool) *config.Config {
	c := &config.Config{}
	c.Server.HTTP.Enabled = httpEnabled
	c.Server.HTTP.TLS.Enabled = httpTLS
	c.Server.GRPC.Enabled = grpcEnabled
	c.Server.GRPC.TLS.Enabled = grpcTLS
	c.Security.RequireTransportTLS = require
	return c
}

func TestCheckTransportTLSPosture(t *testing.T) {
	// require_transport_tls + a cleartext enabled listener → fail closed.
	if err := checkTransportTLSPosture(cfgWith(true, false, false, false, true)); err == nil {
		t.Error("expected failure: HTTP cleartext with require_transport_tls set")
	}
	if err := checkTransportTLSPosture(cfgWith(false, false, true, false, true)); err == nil {
		t.Error("expected failure: gRPC cleartext with require_transport_tls set")
	}
	// require set but both listeners have TLS → ok.
	if err := checkTransportTLSPosture(cfgWith(true, true, true, true, true)); err != nil {
		t.Errorf("TLS on both listeners must pass even with require set: %v", err)
	}
	// require OFF + cleartext → no error (warns only).
	if err := checkTransportTLSPosture(cfgWith(true, false, true, false, false)); err != nil {
		t.Errorf("cleartext without require must not fail: %v", err)
	}
	// a disabled listener is ignored even under require.
	if err := checkTransportTLSPosture(cfgWith(false, false, false, false, true)); err != nil {
		t.Errorf("no enabled listeners must pass: %v", err)
	}
}
