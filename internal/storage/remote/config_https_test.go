package remote

import "testing"

// TestConfig_Validate_RequiresHTTPS pins that the bearer-token-bearing base URL must
// be https (loopback http allowed for dev).
func TestConfig_Validate_RequiresHTTPS(t *testing.T) {
	if err := (&Config{BaseURL: "http://siem.example.com", APIKey: "k"}).Validate(); err == nil {
		t.Fatal("cleartext http base_url must be rejected")
	}
	for _, u := range []string{"https://x.example.com", "http://localhost:8080", "http://127.0.0.1:9000"} {
		if err := (&Config{BaseURL: u, APIKey: "k"}).Validate(); err != nil {
			t.Fatalf("%s should be allowed: %v", u, err)
		}
	}
}
