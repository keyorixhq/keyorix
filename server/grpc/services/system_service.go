package services

import (
	"context"
	"log"

	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SystemService implements the gRPC system service
type SystemService struct {
	// TODO: Add UnimplementedSystemServiceServer when proto is generated
}

// NewSystemService creates a new system service
func NewSystemService() *SystemService {
	return &SystemService{}
}

// GetSystemInfo retrieves system information
func (s *SystemService) GetSystemInfo(ctx context.Context, req interface{}) (interface{}, error) {
	// Get user from context
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Check permissions
	hasPermission := false
	for _, perm := range user.Permissions {
		if perm == "system.read" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return nil, status.Errorf(codes.PermissionDenied, "Insufficient permissions")
	}

	log.Printf("gRPC GetSystemInfo called by user %s", user.Username)

	// TODO: Implement actual system info retrieval logic
	return nil, status.Errorf(codes.Unimplemented, "Method not implemented yet")
}

// GetMetrics retrieves system metrics
func (s *SystemService) GetMetrics(ctx context.Context, req interface{}) (interface{}, error) {
	// Get user from context
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Check permissions
	hasPermission := false
	for _, perm := range user.Permissions {
		if perm == "system.read" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return nil, status.Errorf(codes.PermissionDenied, "Insufficient permissions")
	}

	log.Printf("gRPC GetMetrics called by user %s", user.Username)

	// TODO: Implement actual metrics retrieval logic
	return nil, status.Errorf(codes.Unimplemented, "Method not implemented yet")
}

// HealthCheck provides health check functionality
func (s *SystemService) HealthCheck(ctx context.Context, req interface{}) (interface{}, error) {
	// Health check is typically public, no authentication required
	log.Println("gRPC HealthCheck called")

	// TODO: Implement actual health check logic
	return nil, status.Errorf(codes.Unimplemented, "Method not implemented yet")
}
