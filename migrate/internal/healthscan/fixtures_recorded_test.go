package healthscan

import (
	"context"
	"strings"
	"testing"
)

// Recorded fixtures — SESSION-G4's "unit tests per check against recorded fixture responses
// (Vault 1.15–1.20 shapes + OpenBao 2.x)". These bytes are copy-pasted VERBATIM from real
// `curl` output against a real `hashicorp/vault:1.15` dev server and a real
// `openbao/openbao:2.0` dev server (the same images .github/workflows/ci.yml's `migrate` job
// pins), captured while writing this PR — not hand-typed approximations of what the shape
// "should" look like. This file intentionally records ONLY Vault 1.15.6 and OpenBao 2.0.3 —
// this build never ran against 1.16/1.17/1.18/1.19/1.20 directly. The claim for that wider
// range is narrower and stated explicitly, not implied: these specific endpoints
// (sys/health, sys/seal-status, sys/audit, sys/auth, sys/mounts, sys/config/state/sanitized)
// are part of Vault's long-stable system HTTP API and have carried the same field set across
// that entire minor-version range per HashiCorp's own API documentation — this file is evidence
// the decode logic is correct against SOME real server, not evidence every version in that
// range was independently exercised. TestIntegration_FullScanAgainstRealServer
// (integration_test.go) is what actually runs against a live container in CI, once per matrix
// leg (vault, openbao).
const recordedVaultHealth = `{"initialized":true,"sealed":false,"standby":false,"performance_standby":false,"replication_performance_mode":"disabled","replication_dr_mode":"disabled","server_time_utc":1790611051,"version":"1.15.6","cluster_name":"vault-cluster-d47822c5","cluster_id":"c4cc3263-ba55-ea52-06d7-ace3cd0c5140"}`

const recordedVaultSealStatus = `{"type":"shamir","initialized":true,"sealed":false,"t":1,"n":1,"progress":0,"nonce":"","version":"1.15.6","build_date":"2024-02-28T17:07:34Z","migration":false,"cluster_name":"vault-cluster-d47822c5","cluster_id":"c4cc3263-ba55-ea52-06d7-ace3cd0c5140","recovery_seal":false,"storage_type":"inmem"}`

const recordedVaultAudit = `{"request_id":"216081b4-0d16-3f9a-1368-ac1726272ff6","lease_id":"","renewable":false,"lease_duration":0,"data":{},"wrap_info":null,"warnings":null,"auth":null}`

const recordedVaultAuth = `{"request_id":"32a6b450-0b75-b7fc-be35-d99e1a99034d","lease_id":"","renewable":false,"lease_duration":0,"data":{"token/":{"accessor":"auth_token_3a8626bd","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0,"token_type":"default-service"},"description":"token based credentials","external_entropy_access":false,"local":false,"options":null,"plugin_version":"","running_plugin_version":"v1.15.6+builtin.vault","running_sha256":"","seal_wrap":false,"type":"token","uuid":"90522c1a-0152-1a5f-4170-c7905fe7f5a3"}},"wrap_info":null,"warnings":null,"auth":null}`

const recordedVaultMounts = `{"request_id":"c5d29466-d6c7-82b5-4fd3-572794b535db","lease_id":"","renewable":false,"lease_duration":0,"data":{"cubbyhole/":{"accessor":"cubbyhole_4dcef9df","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"per-token private secret storage","external_entropy_access":false,"local":true,"options":null,"plugin_version":"","running_plugin_version":"v1.15.6+builtin.vault","running_sha256":"","seal_wrap":false,"type":"cubbyhole","uuid":"5cc525d2-4372-5d6b-5b1b-91a264e6a977"},"identity/":{"accessor":"identity_66dd6ae4","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0,"passthrough_request_headers":["Authorization"]},"description":"identity store","external_entropy_access":false,"local":false,"options":null,"plugin_version":"","running_plugin_version":"v1.15.6+builtin.vault","running_sha256":"","seal_wrap":false,"type":"identity","uuid":"7c803013-8ae1-6e8c-baae-c107bd8a00f0"},"secret/":{"accessor":"kv_c5c2df7f","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"deprecation_status":"supported","description":"key/value secret storage","external_entropy_access":false,"local":false,"options":{"version":"2"},"plugin_version":"","running_plugin_version":"v0.16.1+builtin","running_sha256":"","seal_wrap":false,"type":"kv","uuid":"9b4402a1-3494-3a83-fe00-c464409efb67"},"sys/":{"accessor":"system_48995c4e","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0,"passthrough_request_headers":["Accept"]},"description":"system endpoints used for control, policy and debugging","external_entropy_access":false,"local":false,"options":null,"plugin_version":"","running_plugin_version":"v1.15.6+builtin.vault","running_sha256":"","seal_wrap":true,"type":"system","uuid":"03c26073-e4e7-e7c7-01fb-e4c0fc39a21d"}},"wrap_info":null,"warnings":null,"auth":null}`

const recordedVaultSanitizedConfig = `{"request_id":"f790c899-6da3-6321-0cb2-4913d0a1dcbb","lease_id":"","renewable":false,"lease_duration":0,"data":{"administrative_namespace_path":"","api_addr":"","cache_size":0,"cluster_addr":"","cluster_cipher_suites":"","cluster_name":"","default_lease_ttl":0,"default_max_request_duration":0,"detect_deadlocks":"","disable_cache":false,"disable_clustering":false,"disable_indexing":false,"disable_mlock":true,"disable_performance_standby":false,"disable_printable_check":false,"disable_sealwrap":false,"disable_sentinel_trace":false,"enable_response_header_hostname":false,"enable_response_header_raft_node_id":false,"enable_ui":true,"experiments":null,"imprecise_lease_role_tracking":false,"introspection_endpoint":false,"listeners":[{"config":{"address":"127.0.0.1:8200","proxy_protocol_authorized_addrs":"127.0.0.1:8200","proxy_protocol_behavior":"allow_authorized","tls_disable":true},"type":"tcp"}],"log_format":"","log_level":"","log_requests_level":"","max_lease_ttl":0,"pid_file":"","plugin_directory":"","plugin_file_permissions":0,"plugin_file_uid":0,"raw_storage_endpoint":false,"seals":[{"disabled":false,"name":"shamir","priority":1,"type":"shamir"}],"storage":{"cluster_addr":"","disable_clustering":false,"redirect_addr":"","type":"inmem"}},"wrap_info":null,"warnings":null,"auth":null}`

const recordedOpenBaoHealth = `{"initialized":true,"sealed":false,"standby":false,"performance_standby":false,"replication_performance_mode":"disabled","replication_dr_mode":"disabled","server_time_utc":1790611067,"version":"2.0.3","cluster_name":"vault-cluster-53cbd77b","cluster_id":"c287c3d0-9741-b7af-cbce-d55b3087d671"}`

const recordedOpenBaoSealStatus = `{"type":"shamir","initialized":true,"sealed":false,"t":1,"n":1,"progress":0,"nonce":"","version":"2.0.3","build_date":"2024-11-15T16:54:47Z","migration":false,"cluster_name":"vault-cluster-53cbd77b","cluster_id":"c287c3d0-9741-b7af-cbce-d55b3087d671","recovery_seal":false,"storage_type":"inmem"}`

const recordedOpenBaoAudit = `{"request_id":"45a83059-36f6-ed9b-9351-42b8d6d3f3bc","lease_id":"","renewable":false,"lease_duration":0,"data":{},"wrap_info":null,"warnings":null,"auth":null}`

func TestCheckVersionEOL_RecordedVaultFixture(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{"/v1/sys/health": recordedVaultHealth})
	res := checkVersionEOL(context.Background(), c)
	if res.Finding == nil {
		t.Fatalf("expected a finding, got %+v", res)
	}
	if !strings.Contains(res.Finding.Evidence, "Vault 1.15.6") {
		t.Errorf("evidence = %q, want it to name Vault 1.15.6", res.Finding.Evidence)
	}
}

func TestCheckVersionEOL_RecordedOpenBaoFixture(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{"/v1/sys/health": recordedOpenBaoHealth})
	res := checkVersionEOL(context.Background(), c)
	if res.Finding == nil {
		t.Fatalf("expected a finding, got %+v", res)
	}
	if !strings.Contains(res.Finding.Evidence, "OpenBao 2.0.3") {
		t.Errorf("evidence = %q, want it to name OpenBao 2.0.3", res.Finding.Evidence)
	}
}

func TestCheckSeal_RecordedVaultFixture(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{"/v1/sys/seal-status": recordedVaultSealStatus})
	res := checkSeal(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityHigh {
		t.Fatalf("expected high severity (1-of-1 shamir) against the recorded Vault fixture, got %+v", res)
	}
}

func TestCheckSeal_RecordedOpenBaoFixture(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{"/v1/sys/seal-status": recordedOpenBaoSealStatus})
	res := checkSeal(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityHigh {
		t.Fatalf("expected high severity (1-of-1 shamir) against the recorded OpenBao fixture, got %+v", res)
	}
}

func TestCheckAuditDevices_RecordedFixtures(t *testing.T) {
	for name, fixture := range map[string]string{"vault": recordedVaultAudit, "openbao": recordedOpenBaoAudit} {
		t.Run(name, func(t *testing.T) {
			c, _ := fakeServer(t, map[string]string{"/v1/sys/audit": fixture})
			res := checkAuditDevices(context.Background(), c)
			if res.Finding == nil || res.Finding.Severity != SeverityCritical {
				t.Fatalf("expected critical (no audit device) against the recorded %s fixture, got %+v", name, res)
			}
		})
	}
}

func TestCheckAuthMethods_RecordedVaultFixture(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{"/v1/sys/auth": recordedVaultAuth})
	res := checkAuthMethods(context.Background(), c)
	if res.Finding == nil {
		t.Fatalf("expected a finding, got %+v", res)
	}
	if !strings.Contains(res.Finding.Evidence, "token/(token)") {
		t.Errorf("evidence = %q, want the token/ mount decoded", res.Finding.Evidence)
	}
}

func TestCheckSecretsEnginesInventory_RecordedVaultFixture(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{"/v1/sys/mounts": recordedVaultMounts})
	res := checkSecretsEnginesInventory(context.Background(), c)
	if res.Finding == nil {
		t.Fatalf("expected a finding, got %+v", res)
	}
	if !strings.Contains(res.Finding.Evidence, "KV v2: 1") {
		t.Errorf("evidence = %q, want the real secret/ KV v2 mount counted", res.Finding.Evidence)
	}
}

func TestCheckTLSListener_RecordedVaultFixture(t *testing.T) {
	// The recorded dev-mode fixture has tls_disable:true — a real, accurate signal (dev mode
	// really does run without TLS), not a contrived test case.
	c, _ := fakeServer(t, map[string]string{"/v1/sys/config/state/sanitized": recordedVaultSanitizedConfig})
	res := checkTLSListener(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityCritical {
		t.Fatalf("expected critical (TLS disabled) against the recorded fixture, got %+v", res)
	}
}
