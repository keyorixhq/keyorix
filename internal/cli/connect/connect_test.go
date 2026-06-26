package connect

import "testing"

func TestRequireSecureEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		insecure bool
		wantErr  bool
	}{
		{"https allowed", "https://keyorix.example.com", false, false},
		{"http loopback allowed", "http://localhost:8080", false, false},
		{"http 127.0.0.1 allowed", "http://127.0.0.1:8080", false, false},
		{"http remote refused", "http://server.example.com", false, true},
		{"http remote allowed with --insecure", "http://server.example.com", true, false},
		{"garbage endpoint refused", "://nope", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireSecureEndpoint(tc.endpoint, tc.insecure)
			if tc.wantErr && err == nil {
				t.Errorf("requireSecureEndpoint(%q, %v) = nil; want error", tc.endpoint, tc.insecure)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("requireSecureEndpoint(%q, %v) = %v; want nil", tc.endpoint, tc.insecure, err)
			}
		})
	}
}
