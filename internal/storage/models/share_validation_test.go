package models

import (
	"testing"
	"time"
)

func TestValidateShareRecord(t *testing.T) {
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
			name: "missing secret ID",
			share: &ShareRecord{
				OwnerID:     1,
				RecipientID: 2,
				Permission:  "read",
			},
			wantErr: true,
		},
		{
			name: "missing owner ID",
			share: &ShareRecord{
				SecretID:    1,
				RecipientID: 2,
				Permission:  "read",
			},
			wantErr: true,
		},
		{
			name: "missing recipient ID",
			share: &ShareRecord{
				SecretID:   1,
				OwnerID:    2,
				Permission: "read",
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
			},
			wantErr: true,
		},
		{
			name: "valid share record with read permission",
			share: &ShareRecord{
				SecretID:    1,
				OwnerID:     2,
				RecipientID: 3,
				Permission:  "read",
			},
			wantErr: false,
		},
		{
			name: "valid share record with write permission",
			share: &ShareRecord{
				SecretID:    1,
				OwnerID:     2,
				RecipientID: 3,
				Permission:  "write",
			},
			wantErr: false,
		},
		{
			name: "empty permission should default to read",
			share: &ShareRecord{
				SecretID:    1,
				OwnerID:     2,
				RecipientID: 3,
				Permission:  "",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateShareRecord(tt.share)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateShareRecord() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check default values are set when validation passes
			if err == nil && tt.share != nil {
				if tt.share.Permission == "" && tt.share.Permission != "read" {
					t.Errorf("Default permission not set, got: %s, want: read", tt.share.Permission)
				}
				if tt.share.CreatedAt.IsZero() {
					t.Error("CreatedAt timestamp not set")
				}
				if tt.share.UpdatedAt.IsZero() {
					t.Error("UpdatedAt timestamp not set")
				}
			}
		})
	}
}

func TestValidateShareUpdate(t *testing.T) {
	initialTime := time.Now().Add(-time.Hour)

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
			name: "missing share ID",
			share: &ShareRecord{
				SecretID:    1,
				OwnerID:     2,
				RecipientID: 3,
				Permission:  "read",
			},
			wantErr: true,
		},
		{
			name: "invalid permission",
			share: &ShareRecord{
				ID:          1,
				SecretID:    1,
				OwnerID:     2,
				RecipientID: 3,
				Permission:  "invalid",
			},
			wantErr: true,
		},
		{
			name: "valid share update with read permission",
			share: &ShareRecord{
				ID:          1,
				SecretID:    1,
				OwnerID:     2,
				RecipientID: 3,
				Permission:  "read",
				UpdatedAt:   initialTime,
			},
			wantErr: false,
		},
		{
			name: "valid share update with write permission",
			share: &ShareRecord{
				ID:          1,
				SecretID:    1,
				OwnerID:     2,
				RecipientID: 3,
				Permission:  "write",
				UpdatedAt:   initialTime,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateShareUpdate(tt.share)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateShareUpdate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check that UpdatedAt is updated when validation passes
			if err == nil && tt.share != nil {
				if !tt.share.UpdatedAt.After(initialTime) {
					t.Error("UpdatedAt timestamp not updated")
				}
			}
		})
	}
}
