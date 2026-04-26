package models

import (
	"testing"
)

func TestValidateGroupShare(t *testing.T) {
	tests := []struct {
		name    string
		share   *ShareRecord
		wantErr bool
	}{
		{
			name:    "nil share record",
			share:   nil,
			wantErr: true,
		},
		{
			name: "not a group share",
			share: &ShareRecord{
				SecretID:    1,
				OwnerID:     2,
				RecipientID: 3,
				Permission:  "read",
				IsGroup:     false,
			},
			wantErr: true,
		},
		{
			name: "missing secret ID",
			share: &ShareRecord{
				OwnerID:     1,
				RecipientID: 2,
				Permission:  "read",
				IsGroup:     true,
			},
			wantErr: true,
		},
		{
			name: "missing owner ID",
			share: &ShareRecord{
				SecretID:    1,
				RecipientID: 2,
				Permission:  "read",
				IsGroup:     true,
			},
			wantErr: true,
		},
		{
			name: "missing recipient ID (group ID)",
			share: &ShareRecord{
				SecretID:   1,
				OwnerID:    2,
				Permission: "read",
				IsGroup:    true,
			},
			wantErr: true,
		},
		{
			name: "invalid permission",
			share: &ShareRecord{
				SecretID:    1,
				OwnerID:     2,
				RecipientID: 3,
				Permission:  "invalid",
				IsGroup:     true,
			},
			wantErr: true,
		},
		{
			name: "valid group share with read permission",
			share: &ShareRecord{
				SecretID:    1,
				OwnerID:     2,
				RecipientID: 3, // Group ID
				Permission:  "read",
				IsGroup:     true,
			},
			wantErr: false,
		},
		{
			name: "valid group share with write permission",
			share: &ShareRecord{
				SecretID:    1,
				OwnerID:     2,
				RecipientID: 3, // Group ID
				Permission:  "write",
				IsGroup:     true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateGroupShare(tt.share)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateGroupShare() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
