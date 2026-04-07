package services

import (
	"context"
	"log"

	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UserService implements the gRPC user service
type UserService struct {
	// TODO: Add UnimplementedUserServiceServer when proto is generated
}

// NewUserService creates a new user service
func NewUserService() *UserService {
	return &UserService{}
}

// CreateUser creates a new user
func (s *UserService) CreateUser(ctx context.Context, req interface{}) (interface{}, error) {
	// Get user from context
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Check permissions
	hasPermission := false
	for _, perm := range user.Permissions {
		if perm == "users.write" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return nil, status.Errorf(codes.PermissionDenied, "Insufficient permissions")
	}

	log.Printf("gRPC CreateUser called by user %s", user.Username)

	// TODO: Implement actual user creation logic
	return nil, status.Errorf(codes.Unimplemented, "Method not implemented yet")
}

// GetUser retrieves a user by ID
func (s *UserService) GetUser(ctx context.Context, req interface{}) (interface{}, error) {
	// Get user from context
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Check permissions
	hasPermission := false
	for _, perm := range user.Permissions {
		if perm == "users.read" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return nil, status.Errorf(codes.PermissionDenied, "Insufficient permissions")
	}

	log.Printf("gRPC GetUser called by user %s", user.Username)

	// TODO: Implement actual user retrieval logic
	return nil, status.Errorf(codes.Unimplemented, "Method not implemented yet")
}

// UpdateUser updates an existing user
func (s *UserService) UpdateUser(ctx context.Context, req interface{}) (interface{}, error) {
	// Get user from context
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Check permissions
	hasPermission := false
	for _, perm := range user.Permissions {
		if perm == "users.write" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return nil, status.Errorf(codes.PermissionDenied, "Insufficient permissions")
	}

	log.Printf("gRPC UpdateUser called by user %s", user.Username)

	// TODO: Implement actual user update logic
	return nil, status.Errorf(codes.Unimplemented, "Method not implemented yet")
}

// DeleteUser deletes a user
func (s *UserService) DeleteUser(ctx context.Context, req interface{}) (interface{}, error) {
	// Get user from context
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Check permissions
	hasPermission := false
	for _, perm := range user.Permissions {
		if perm == "users.delete" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return nil, status.Errorf(codes.PermissionDenied, "Insufficient permissions")
	}

	log.Printf("gRPC DeleteUser called by user %s", user.Username)

	// TODO: Implement actual user deletion logic
	return nil, status.Errorf(codes.Unimplemented, "Method not implemented yet")
}

// ListUsers lists users with filtering and pagination
func (s *UserService) ListUsers(ctx context.Context, req interface{}) (interface{}, error) {
	// Get user from context
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Check permissions
	hasPermission := false
	for _, perm := range user.Permissions {
		if perm == "users.read" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return nil, status.Errorf(codes.PermissionDenied, "Insufficient permissions")
	}

	log.Printf("gRPC ListUsers called by user %s", user.Username)

	// TODO: Implement actual user listing logic
	return nil, status.Errorf(codes.Unimplemented, "Method not implemented yet")
}
