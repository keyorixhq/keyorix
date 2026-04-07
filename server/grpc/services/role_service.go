package services

import (
	"context"
	"log"

	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RoleService implements the gRPC role service
type RoleService struct {
	// TODO: Add UnimplementedRoleServiceServer when proto is generated
}

// NewRoleService creates a new role service
func NewRoleService() *RoleService {
	return &RoleService{}
}

// CreateRole creates a new role
func (s *RoleService) CreateRole(ctx context.Context, req interface{}) (interface{}, error) {
	// Get user from context
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Check permissions
	hasPermission := false
	for _, perm := range user.Permissions {
		if perm == "roles.write" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return nil, status.Errorf(codes.PermissionDenied, "Insufficient permissions")
	}

	log.Printf("gRPC CreateRole called by user %s", user.Username)

	// TODO: Implement actual role creation logic
	return nil, status.Errorf(codes.Unimplemented, "Method not implemented yet")
}

// GetRole retrieves a role by ID
func (s *RoleService) GetRole(ctx context.Context, req interface{}) (interface{}, error) {
	// Get user from context
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Check permissions
	hasPermission := false
	for _, perm := range user.Permissions {
		if perm == "roles.read" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return nil, status.Errorf(codes.PermissionDenied, "Insufficient permissions")
	}

	log.Printf("gRPC GetRole called by user %s", user.Username)

	// TODO: Implement actual role retrieval logic
	return nil, status.Errorf(codes.Unimplemented, "Method not implemented yet")
}

// UpdateRole updates an existing role
func (s *RoleService) UpdateRole(ctx context.Context, req interface{}) (interface{}, error) {
	// Get user from context
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Check permissions
	hasPermission := false
	for _, perm := range user.Permissions {
		if perm == "roles.write" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return nil, status.Errorf(codes.PermissionDenied, "Insufficient permissions")
	}

	log.Printf("gRPC UpdateRole called by user %s", user.Username)

	// TODO: Implement actual role update logic
	return nil, status.Errorf(codes.Unimplemented, "Method not implemented yet")
}

// DeleteRole deletes a role
func (s *RoleService) DeleteRole(ctx context.Context, req interface{}) (interface{}, error) {
	// Get user from context
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Check permissions
	hasPermission := false
	for _, perm := range user.Permissions {
		if perm == "roles.delete" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return nil, status.Errorf(codes.PermissionDenied, "Insufficient permissions")
	}

	log.Printf("gRPC DeleteRole called by user %s", user.Username)

	// TODO: Implement actual role deletion logic
	return nil, status.Errorf(codes.Unimplemented, "Method not implemented yet")
}

// AssignRole assigns a role to a user
func (s *RoleService) AssignRole(ctx context.Context, req interface{}) (interface{}, error) {
	// Get user from context
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Check permissions
	hasPermission := false
	for _, perm := range user.Permissions {
		if perm == "roles.assign" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return nil, status.Errorf(codes.PermissionDenied, "Insufficient permissions")
	}

	log.Printf("gRPC AssignRole called by user %s", user.Username)

	// TODO: Implement actual role assignment logic
	return nil, status.Errorf(codes.Unimplemented, "Method not implemented yet")
}

// RemoveRole removes a role from a user
func (s *RoleService) RemoveRole(ctx context.Context, req interface{}) (interface{}, error) {
	// Get user from context
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Check permissions
	hasPermission := false
	for _, perm := range user.Permissions {
		if perm == "roles.assign" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return nil, status.Errorf(codes.PermissionDenied, "Insufficient permissions")
	}

	log.Printf("gRPC RemoveRole called by user %s", user.Username)

	// TODO: Implement actual role removal logic
	return nil, status.Errorf(codes.Unimplemented, "Method not implemented yet")
}

// ListRoles lists roles with filtering and pagination
func (s *RoleService) ListRoles(ctx context.Context, req interface{}) (interface{}, error) {
	// Get user from context
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Check permissions
	hasPermission := false
	for _, perm := range user.Permissions {
		if perm == "roles.read" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return nil, status.Errorf(codes.PermissionDenied, "Insufficient permissions")
	}

	log.Printf("gRPC ListRoles called by user %s", user.Username)

	// TODO: Implement actual role listing logic
	return nil, status.Errorf(codes.Unimplemented, "Method not implemented yet")
}
