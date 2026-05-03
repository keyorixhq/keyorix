package services

import (
	"context"
	"fmt"
	"log"
	"math"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/utils/safeconv"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// SecretGRPCService implements the gRPC secret service
type SecretGRPCService struct {
	secretService *core.KeyorixCore
	// TODO: Add UnimplementedSecretServiceServer when proto is generated
}

// NewSecretService creates a new secret gRPC service
func NewSecretService() (*SecretGRPCService, error) {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorInitializationFailed", nil), err)
	}

	// Connect to database
	db, err := gorm.Open(sqlite.Open(cfg.Storage.Database.Path), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Auto-migrate models
	if err := db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	// Initialize storage and core service
	storageImpl := store.NewLocalStorage(db)
	secretService := core.NewKeyorixCore(storageImpl)

	return &SecretGRPCService{
		secretService: secretService,
	}, nil
}

// CreateSecretRequest represents a gRPC create secret request
type CreateSecretRequest struct {
	Name        string            `json:"name"`
	Value       string            `json:"value"`
	Namespace   string            `json:"namespace"`
	Zone        string            `json:"zone"`
	Environment string            `json:"environment"`
	Type        string            `json:"type,omitempty"`
	MaxReads    *int32            `json:"max_reads,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
}

// SecretResponse represents a gRPC secret response
type SecretResponse struct {
	Id          uint32            `json:"id"`
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Zone        string            `json:"zone"`
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

// CreateSecret creates a new secret via gRPC
func (s *SecretGRPCService) CreateSecret(ctx context.Context, req *CreateSecretRequest) (*SecretResponse, error) {
	// Get user from context
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Check permissions
	if !s.hasPermission(user.Permissions, "secrets.write") {
		return nil, status.Errorf(codes.PermissionDenied, "Insufficient permissions for secret creation")
	}

	log.Printf("gRPC CreateSecret called by user %s for secret %s", user.Username, req.Name)

	// Validate request
	if err := s.validateCreateSecretRequest(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request: %v", err)
	}

	// Convert to service request
	var maxReads *int
	if req.MaxReads != nil {
		maxReadsInt := int(*req.MaxReads)
		maxReads = &maxReadsInt
	}

	serviceReq := &core.CreateSecretRequest{
		Name:          req.Name,
		Value:         []byte(req.Value),
		NamespaceID:   1, // TODO: Convert namespace string to ID
		ZoneID:        1, // TODO: Convert zone string to ID
		EnvironmentID: 1, // TODO: Convert environment string to ID
		Type:          req.Type,
		MaxReads:      maxReads,
		Metadata:      req.Metadata,
		Tags:          req.Tags,
		CreatedBy:     user.Username,
	}

	// Call service
	secret, err := s.secretService.CreateSecret(ctx, serviceReq)
	if err != nil {
		log.Printf("Error creating secret via gRPC: %v", err)
		if strings.Contains(err.Error(), "already exists") {
			return nil, status.Errorf(codes.AlreadyExists, "Secret with this name already exists")
		}
		return nil, status.Errorf(codes.Internal, "Failed to create secret")
	}

	// Convert response
	return s.convertToGRPCSecretResponse(secret), nil
}

// GetSecret retrieves a secret by ID via gRPC
func (s *SecretGRPCService) GetSecret(ctx context.Context, req *GetSecretRequest) (*SecretResponse, error) {
	// Get user from context
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Check basic permissions
	if !s.hasPermission(user.Permissions, "secrets.read") {
		return nil, status.Errorf(codes.PermissionDenied, "Insufficient permissions for secret access")
	}

	log.Printf("gRPC GetSecret called by user %s for secret ID %d", user.Username, req.Id)

	// Call service with permission check for shared secrets
	secret, err := s.secretService.GetSecretWithPermissionCheck(ctx, uint(req.Id), user.UserID)
	if err != nil {
		log.Printf("Error getting secret via gRPC: %v", err)
		if strings.Contains(err.Error(), "not found") {
			return nil, status.Errorf(codes.NotFound, "Secret not found")
		} else if strings.Contains(err.Error(), "permission denied") {
			return nil, status.Errorf(codes.PermissionDenied, "Access denied to this secret")
		}
		return nil, status.Errorf(codes.Internal, "Failed to get secret")
	}

	// Convert response
	return s.convertToGRPCSecretResponse(secret), nil
}

// GetSecretRequest represents a gRPC get secret request
type GetSecretRequest struct {
	Id           uint32 `json:"id"`
	IncludeValue bool   `json:"include_value"`
}

// ListSecretsRequest represents a gRPC list secrets request
type ListSecretsRequest struct {
	Namespace   string   `json:"namespace,omitempty"`
	Zone        string   `json:"zone,omitempty"`
	Environment string   `json:"environment,omitempty"`
	Type        string   `json:"type,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Page        int32    `json:"page"`
	PageSize    int32    `json:"page_size"`
}

// ListSecretsResponse represents a gRPC list secrets response
type ListSecretsResponse struct {
	Secrets    []*SecretResponse `json:"secrets"`
	Total      int64             `json:"total"`
	Page       int32             `json:"page"`
	PageSize   int32             `json:"page_size"`
	TotalPages int32             `json:"total_pages"`
}

// ListSecrets lists secrets with filtering and pagination via gRPC
func (s *SecretGRPCService) ListSecrets(ctx context.Context, req *ListSecretsRequest) (*ListSecretsResponse, error) {
	// Get user from context
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Check permissions
	if !s.hasPermission(user.Permissions, "secrets.read") {
		return nil, status.Errorf(codes.PermissionDenied, "Insufficient permissions for secret listing")
	}

	log.Printf("gRPC ListSecrets called by user %s", user.Username)

	// Validate pagination
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize < 1 || req.PageSize > 100 {
		req.PageSize = 20
	}

	// Convert to service request
	namespaceID := uint(1)   // TODO: Convert namespace string to ID
	zoneID := uint(1)        // TODO: Convert zone string to ID
	environmentID := uint(1) // TODO: Convert environment string to ID

	filter := &storage.SecretFilter{
		NamespaceID:   &namespaceID,
		ZoneID:        &zoneID,
		EnvironmentID: &environmentID,
		Page:          int(req.Page),
		PageSize:      int(req.PageSize),
	}

	if req.Type != "" {
		filter.Type = &req.Type
	}

	// Call service
	secrets, total, err := s.secretService.ListSecrets(ctx, filter)
	if err != nil {
		log.Printf("Error listing secrets via gRPC: %v", err)
		return nil, status.Errorf(codes.Internal, "Failed to list secrets")
	}

	// Convert response
	grpcSecrets := make([]*SecretResponse, len(secrets))
	for i, secret := range secrets {
		grpcSecrets[i] = s.convertToGRPCSecretResponse(secret)
	}

	var totalPages int32
	if req.PageSize > 0 {
		tp := (total + int64(req.PageSize) - 1) / int64(req.PageSize)
		if tp > int64(math.MaxInt32) {
			tp = math.MaxInt32
		}
		totalPages = int32(tp)
	}

	return &ListSecretsResponse{
		Secrets:    grpcSecrets,
		Total:      total,
		Page:       req.Page,
		PageSize:   req.PageSize,
		TotalPages: totalPages,
	}, nil
}

// Helper methods

// hasPermission checks if user has a specific permission
func (s *SecretGRPCService) hasPermission(permissions []string, required string) bool {
	for _, perm := range permissions {
		if perm == required {
			return true
		}
	}
	return false
}

// validateCreateSecretRequest validates a create secret request
func (s *SecretGRPCService) validateCreateSecretRequest(req *CreateSecretRequest) error {
	if req.Name == "" {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), i18n.T("LabelName", nil))
	}
	if req.Value == "" {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), i18n.T("LabelValue", nil))
	}
	if req.Namespace == "" {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), i18n.T("LabelNamespace", nil))
	}
	if req.Zone == "" {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), i18n.T("LabelZone", nil))
	}
	if req.Environment == "" {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), i18n.T("LabelEnvironment", nil))
	}
	if len(req.Name) > 255 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), i18n.T("LabelName", nil))
	}
	if req.MaxReads != nil && *req.MaxReads < 1 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), i18n.T("LabelMaxReads", nil))
	}
	return nil
}

// convertToGRPCSecretResponse converts service response to gRPC response
func (s *SecretGRPCService) convertToGRPCSecretResponse(secret *models.SecretNode) *SecretResponse {
	var maxReads *int32
	if secret.MaxReads != nil {
		maxReadsInt32, err := safeconv.IntToInt32(*secret.MaxReads)
		if err != nil {
			log.Printf("Warning: MaxReads conversion overflow for secret %d: %v", secret.ID, err)
			maxReadsInt32 = 0
		}
		maxReads = &maxReadsInt32
	}

	return &SecretResponse{
		Id: func() uint32 {
			id, err := safeconv.UintToUint32(secret.ID)
			if err != nil {
				log.Printf("Warning: ID conversion overflow for secret %d: %v", secret.ID, err)
				return 0
			}
			return id
		}(),
		Name:        secret.Name,
		Namespace:   fmt.Sprintf("%d", secret.NamespaceID),   // TODO: Convert ID to name
		Zone:        fmt.Sprintf("%d", secret.ZoneID),        // TODO: Convert ID to name
		Environment: fmt.Sprintf("%d", secret.EnvironmentID), // TODO: Convert ID to name
		Type:        secret.Type,
		MaxReads:    maxReads,
		Metadata:    make(map[string]string), // TODO: Implement metadata
		Tags:        []string{},              // TODO: Implement tags
		CreatedBy:   secret.CreatedBy,
		CreatedAt:   secret.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   secret.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		Version:     1, // TODO: Implement version tracking
	}
}

// UpdateSecret updates an existing secret via gRPC
func (s *SecretGRPCService) UpdateSecret(ctx context.Context, req *UpdateSecretRequest) (*SecretResponse, error) {
	// Get user from context
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Check basic permissions
	if !s.hasPermission(user.Permissions, "secrets.write") {
		return nil, status.Errorf(codes.PermissionDenied, "Insufficient permissions for secret update")
	}

	log.Printf("gRPC UpdateSecret called by user %s for secret ID %d", user.Username, req.Id)

	// Validate request
	if req.Id == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "Secret ID is required")
	}

	// Convert to service request
	var maxReads *int
	if req.MaxReads != nil {
		maxReadsInt := int(*req.MaxReads)
		maxReads = &maxReadsInt
	}

	serviceReq := &core.UpdateSecretRequest{
		ID:        uint(req.Id),
		MaxReads:  maxReads,
		UpdatedBy: user.Username,
		UserID:    user.UserID, // Add user ID for permission checking
	}

	if req.Value != "" {
		serviceReq.Value = []byte(req.Value)
	}

	// Call service with permission check for shared secrets
	secret, err := s.secretService.UpdateSecretWithPermissionCheck(ctx, serviceReq)
	if err != nil {
		log.Printf("Error updating secret via gRPC: %v", err)
		if strings.Contains(err.Error(), "not found") {
			return nil, status.Errorf(codes.NotFound, "Secret not found")
		} else if strings.Contains(err.Error(), "permission denied") {
			return nil, status.Errorf(codes.PermissionDenied, "Access denied to this secret")
		}
		return nil, status.Errorf(codes.Internal, "Failed to update secret")
	}

	// Convert response
	return s.convertToGRPCSecretResponse(secret), nil
}

// UpdateSecretRequest represents a gRPC update secret request
type UpdateSecretRequest struct {
	Id       uint32            `json:"id"`
	Name     string            `json:"name,omitempty"`
	Value    string            `json:"value,omitempty"`
	Type     string            `json:"type,omitempty"`
	MaxReads *int32            `json:"max_reads,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Tags     []string          `json:"tags,omitempty"`
}

// DeleteSecret deletes a secret via gRPC
func (s *SecretGRPCService) DeleteSecret(ctx context.Context, req *DeleteSecretRequest) error {
	// Get user from context
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Check permissions
	if !s.hasPermission(user.Permissions, "secrets.delete") {
		return status.Errorf(codes.PermissionDenied, "Insufficient permissions for secret deletion")
	}

	log.Printf("gRPC DeleteSecret called by user %s for secret ID %d", user.Username, req.Id)

	// Validate request
	if req.Id == 0 {
		return status.Errorf(codes.InvalidArgument, "Secret ID is required")
	}

	// Call service with permission check for shared secrets
	err := s.secretService.DeleteSecretWithPermissionCheck(ctx, uint(req.Id), user.UserID)
	if err != nil {
		log.Printf("Error deleting secret via gRPC: %v", err)
		if strings.Contains(err.Error(), "not found") {
			return status.Errorf(codes.NotFound, "Secret not found")
		} else if strings.Contains(err.Error(), "permission denied") {
			return status.Errorf(codes.PermissionDenied, "Access denied to this secret")
		}
		return status.Errorf(codes.Internal, "Failed to delete secret")
	}

	return nil
}

// DeleteSecretRequest represents a gRPC delete secret request
type DeleteSecretRequest struct {
	Id uint32 `json:"id"`
}
