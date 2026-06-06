package services

// Transitional hand-written secret response types.
//
// SecretService has been migrated to the generated pb.* types (secret_service.go),
// but ShareService.ListSharedSecrets still returns this hand-written shape. These
// types are retained only until ShareService is migrated to the generated proto in
// a subsequent phase, at which point this file should be deleted.

// SecretResponse is the legacy hand-written gRPC secret response.
type SecretResponse struct {
	Id          uint32            `json:"id"`
	Name        string            `json:"name"`
	Project     string            `json:"project"`
	Environment string            `json:"environment"`
	Type        string            `json:"type"`
	MaxReads    *int32            `json:"max_reads"`
	Metadata    map[string]string `json:"metadata"`
	Tags        []string          `json:"tags"`
	CreatedBy   string            `json:"created_by"`
	CreatedAt   string            `json:"created_at"`
	UpdatedAt   string            `json:"updated_at"`
	Version     int32             `json:"version"`
}

// ListSecretsResponse is the legacy hand-written gRPC list-secrets response.
type ListSecretsResponse struct {
	Secrets    []*SecretResponse `json:"secrets"`
	Total      int64             `json:"total"`
	Page       int32             `json:"page"`
	PageSize   int32             `json:"page_size"`
	TotalPages int32             `json:"total_pages"`
}
