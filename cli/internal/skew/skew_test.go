package skew

import "testing"

func TestCheck(t *testing.T) {
	tests := []struct {
		name         string
		cliVersion   string
		cliTargetAPI int
		serverAPI    int
		serverMinCLI string
		wantRefuse   bool
		wantWarning  bool
	}{
		{
			name:         "exact match, fully compatible",
			cliVersion:   "1.4.2",
			cliTargetAPI: 1,
			serverAPI:    1,
			serverMinCLI: "1.0.0",
			wantRefuse:   false,
			wantWarning:  false,
		},
		{
			name:         "same major, CLI older than server epoch: warn",
			cliVersion:   "1.4.2",
			cliTargetAPI: 1,
			serverAPI:    2,
			serverMinCLI: "1.0.0",
			wantRefuse:   false,
			wantWarning:  true,
		},
		{
			name:         "same major, CLI newer than server epoch: warn",
			cliVersion:   "1.4.2",
			cliTargetAPI: 2,
			serverAPI:    1,
			serverMinCLI: "1.0.0",
			wantRefuse:   false,
			wantWarning:  true,
		},
		{
			name:         "different major line vs. minimum: refuse",
			cliVersion:   "1.9.9",
			cliTargetAPI: 1,
			serverAPI:    1,
			serverMinCLI: "2.0.0",
			wantRefuse:   true,
		},
		{
			name:         "same major, below minimum: refuse",
			cliVersion:   "1.2.0",
			cliTargetAPI: 1,
			serverAPI:    1,
			serverMinCLI: "1.5.0",
			wantRefuse:   true,
		},
		{
			name:         "no minimum configured, exact epoch match: compatible",
			cliVersion:   "1.0.0",
			cliTargetAPI: 1,
			serverAPI:    1,
			serverMinCLI: "",
			wantRefuse:   false,
			wantWarning:  false,
		},
		{
			name:         "server predates the version-skew fields (zero api_version): warn, not refuse",
			cliVersion:   "1.0.0",
			cliTargetAPI: 1,
			serverAPI:    0,
			serverMinCLI: "",
			wantRefuse:   false,
			wantWarning:  true,
		},
		{
			name:         "dev build with a minimum configured fails open to the epoch check",
			cliVersion:   "dev",
			cliTargetAPI: 1,
			serverAPI:    1,
			serverMinCLI: "1.5.0",
			wantRefuse:   false,
			wantWarning:  false,
		},
		{
			name:         "minimum satisfied exactly at the floor: allowed",
			cliVersion:   "1.5.0",
			cliTargetAPI: 1,
			serverAPI:    1,
			serverMinCLI: "1.5.0",
			wantRefuse:   false,
			wantWarning:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Check(tt.cliVersion, tt.cliTargetAPI, tt.serverAPI, tt.serverMinCLI)
			if got.Refuse != tt.wantRefuse {
				t.Fatalf("Refuse = %v, want %v (result: %+v)", got.Refuse, tt.wantRefuse, got)
			}
			if tt.wantRefuse && got.Reason == "" {
				t.Fatalf("Refuse=true but Reason is empty")
			}
			gotWarning := got.Warning != ""
			if gotWarning != tt.wantWarning {
				t.Fatalf("warning present = %v, want %v (result: %+v)", gotWarning, tt.wantWarning, got)
			}
		})
	}
}
