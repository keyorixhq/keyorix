package azurekms

import "testing"

func TestParseKeyID(t *testing.T) {
	tests := []struct {
		name                             string
		keyID                            string
		wantVault, wantName, wantVersion string
		wantErr                          bool
	}{
		{
			name:        "versioned",
			keyID:       "https://myvault.vault.azure.net/keys/kek/abc123",
			wantVault:   "https://myvault.vault.azure.net",
			wantName:    "kek",
			wantVersion: "abc123",
		},
		{
			name:      "unversioned uses latest",
			keyID:     "https://myvault.vault.azure.net/keys/kek",
			wantVault: "https://myvault.vault.azure.net",
			wantName:  "kek",
		},
		{
			name:      "trailing slash",
			keyID:     "https://myvault.vault.azure.net/keys/kek/",
			wantVault: "https://myvault.vault.azure.net",
			wantName:  "kek",
		},
		{name: "missing scheme/host", keyID: "/keys/kek/v1", wantErr: true},
		{name: "not a keys path", keyID: "https://myvault.vault.azure.net/secrets/foo", wantErr: true},
		{name: "missing key name", keyID: "https://myvault.vault.azure.net/keys", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vault, name, version, err := parseKeyID(tt.keyID)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got vault=%q name=%q version=%q", vault, name, version)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if vault != tt.wantVault || name != tt.wantName || version != tt.wantVersion {
				t.Fatalf("got (%q,%q,%q), want (%q,%q,%q)", vault, name, version, tt.wantVault, tt.wantName, tt.wantVersion)
			}
		})
	}
}
