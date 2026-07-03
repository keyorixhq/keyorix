package grpc

import (
	"crypto/tls"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// #172: gRPC AutoCert mode must not silently discard the hardened
// MinVersion/CipherSuites — createGRPCTLSConfig must apply the same hardening on the
// AutoCert branch as it does on the non-AutoCert (manual cert/key) branch below.
func TestCreateGRPCTLSConfig_AutoCertAppliesHardening(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.GRPC.TLS.Enabled = true
	cfg.Server.GRPC.TLS.AutoCert = true

	tlsConfig, err := createGRPCTLSConfig(cfg)
	if err != nil {
		t.Fatalf("createGRPCTLSConfig: %v", err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %v, want tls.VersionTLS12", tlsConfig.MinVersion)
	}
	if len(tlsConfig.CipherSuites) == 0 {
		t.Fatal("CipherSuites must not be empty on the AutoCert branch")
	}
}
