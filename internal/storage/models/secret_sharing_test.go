package models

import (
	"testing"
)

func TestSecretNode_IsOwner(t *testing.T) {
	tests := []struct {
		name   string
		secret *SecretNode
		userID uint
		want   bool
	}{
		{
			name: "user is owner",
			secret: &SecretNode{
				OwnerID: 1,
			},
			userID: 1,
			want:   true,
		},
		{
			name: "user is not owner",
			secret: &SecretNode{
				OwnerID: 1,
			},
			userID: 2,
			want:   false,
		},
		{
			name: "zero user ID",
			secret: &SecretNode{
				OwnerID: 1,
			},
			userID: 0,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.secret.IsOwner(tt.userID); got != tt.want {
				t.Errorf("SecretNode.IsOwner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSecretNode_SetOwner(t *testing.T) {
	tests := []struct {
		name    string
		secret  *SecretNode
		userID  uint
		wantErr bool
	}{
		{
			name:    "valid owner ID",
			secret:  &SecretNode{},
			userID:  1,
			wantErr: false,
		},
		{
			name:    "zero owner ID",
			secret:  &SecretNode{},
			userID:  0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.secret.SetOwner(tt.userID)
			if (err != nil) != tt.wantErr {
				t.Errorf("SecretNode.SetOwner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil && tt.secret.OwnerID != tt.userID {
				t.Errorf("SecretNode.SetOwner() did not set OwnerID correctly, got = %v, want %v", tt.secret.OwnerID, tt.userID)
			}
		})
	}
}

func TestSecretNode_ValidateOwnership(t *testing.T) {
	tests := []struct {
		name    string
		secret  *SecretNode
		wantErr bool
	}{
		{
			name: "has owner",
			secret: &SecretNode{
				OwnerID: 1,
			},
			wantErr: false,
		},
		{
			name: "no owner",
			secret: &SecretNode{
				OwnerID: 0,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.secret.ValidateOwnership(); (err != nil) != tt.wantErr {
				t.Errorf("SecretNode.ValidateOwnership() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePermissionLevel(t *testing.T) {
	tests := []struct {
		name       string
		permission string
		wantErr    bool
	}{
		{
			name:       "read permission",
			permission: "read",
			wantErr:    false,
		},
		{
			name:       "write permission",
			permission: "write",
			wantErr:    false,
		},
		{
			name:       "invalid permission",
			permission: "invalid",
			wantErr:    true,
		},
		{
			name:       "empty permission",
			permission: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidatePermissionLevel(tt.permission); (err != nil) != tt.wantErr {
				t.Errorf("ValidatePermissionLevel() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
