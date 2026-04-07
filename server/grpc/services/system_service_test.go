package services

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/local"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestHelper provides consistent test setup for system service tests
type SystemTestHelper struct {
	CoreService *core.KeyorixCore
	DB          *gorm.DB
}

// NewSystemTestHelper creates a new test helper with in-memory database and core service
func NewSystemTestHelper(t *testing.T) *SystemTestHelper {
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	// Create an in-memory database for testing
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate models
	err = db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.Role{}, &models.ShareRecord{})
	require.NoError(t, err)

	// Create storage
	storage := local.NewLocalStorage(db)

	// Create core service
	coreService := core.NewKeyorixCore(storage)

	return &SystemTestHelper{
		CoreService: coreService,
		DB:          db,
	}
}

// CreateTestUser creates a test user in the database
func (h *SystemTestHelper) CreateTestUser(t *testing.T, username string, userID uint) *models.User {
	user := &models.User{
		ID:       userID,
		Username: username,
	}
	err := h.DB.Create(user).Error
	require.NoError(t, err)
	return user
}

// CreateUserContext creates a context with user information for testing
func CreateSystemUserContext(userCtx *interceptors.UserContext) context.Context {
	if userCtx == nil {
		return context.Background()
	}
	return context.WithValue(context.Background(), interceptors.GetUserContextKey(), userCtx)
}

func TestNewSystemService(t *testing.T) {
	service := NewSystemService()
	assert.NotNil(t, service)
}

func TestSystemService_GetSystemInfo(t *testing.T) {
	helper := NewSystemTestHelper(t)
	service := NewSystemService()

	tests := []struct {
		name          string
		userCtx       *interceptors.UserContext
		expectedError codes.Code
		setupUser     bool
	}{
		{
			name: "successful call with valid permissions",
			userCtx: &interceptors.UserContext{
				UserID:      1,
				Username:    "admin",
				Permissions: []string{"system.read"},
			},
			expectedError: codes.Unimplemented, // Method not implemented yet
			setupUser:     true,
		},
		{
			name:          "unauthenticated user",
			userCtx:       nil,
			expectedError: codes.Unauthenticated,
			setupUser:     false,
		},
		{
			name: "insufficient permissions",
			userCtx: &interceptors.UserContext{
				UserID:      2,
				Username:    "user",
				Permissions: []string{"secrets.read"}, // missing system.read
			},
			expectedError: codes.PermissionDenied,
			setupUser:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test user if needed
			if tt.setupUser && tt.userCtx != nil {
				helper.CreateTestUser(t, tt.userCtx.Username, tt.userCtx.UserID)
			}

			// Create context with user
			ctx := CreateSystemUserContext(tt.userCtx)

			// Call service method
			response, err := service.GetSystemInfo(ctx, nil)

			// Check error code
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, tt.expectedError, st.Code())
			assert.Nil(t, response)
		})
	}
}

func TestSystemService_GetMetrics(t *testing.T) {
	helper := NewSystemTestHelper(t)
	service := NewSystemService()

	tests := []struct {
		name          string
		userCtx       *interceptors.UserContext
		expectedError codes.Code
		setupUser     bool
	}{
		{
			name: "successful call with valid permissions",
			userCtx: &interceptors.UserContext{
				UserID:      1,
				Username:    "admin",
				Permissions: []string{"system.read"},
			},
			expectedError: codes.Unimplemented, // Method not implemented yet
			setupUser:     true,
		},
		{
			name:          "unauthenticated user",
			userCtx:       nil,
			expectedError: codes.Unauthenticated,
			setupUser:     false,
		},
		{
			name: "insufficient permissions",
			userCtx: &interceptors.UserContext{
				UserID:      2,
				Username:    "user",
				Permissions: []string{"secrets.read"}, // missing system.read
			},
			expectedError: codes.PermissionDenied,
			setupUser:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test user if needed
			if tt.setupUser && tt.userCtx != nil {
				helper.CreateTestUser(t, tt.userCtx.Username, tt.userCtx.UserID)
			}

			// Create context with user
			ctx := CreateSystemUserContext(tt.userCtx)

			// Call service method
			response, err := service.GetMetrics(ctx, nil)

			// Check error code
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, tt.expectedError, st.Code())
			assert.Nil(t, response)
		})
	}
}

func TestSystemService_HealthCheck(t *testing.T) {
	helper := NewSystemTestHelper(t)
	service := NewSystemService()

	tests := []struct {
		name          string
		userCtx       *interceptors.UserContext
		expectedError codes.Code
		setupUser     bool
	}{
		{
			name:          "health check without authentication",
			userCtx:       nil,
			expectedError: codes.Unimplemented, // Method not implemented yet
			setupUser:     false,
		},
		{
			name: "health check with authenticated user",
			userCtx: &interceptors.UserContext{
				UserID:      1,
				Username:    "admin",
				Permissions: []string{"system.read"},
			},
			expectedError: codes.Unimplemented, // Method not implemented yet
			setupUser:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test user if needed
			if tt.setupUser && tt.userCtx != nil {
				helper.CreateTestUser(t, tt.userCtx.Username, tt.userCtx.UserID)
			}

			// Create context with user (or without for health check)
			ctx := CreateSystemUserContext(tt.userCtx)

			// Call service method
			response, err := service.HealthCheck(ctx, nil)

			// Check error code
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, tt.expectedError, st.Code())
			assert.Nil(t, response)
		})
	}
}

func TestSystemService_PermissionValidation(t *testing.T) {
	helper := NewSystemTestHelper(t)
	service := NewSystemService()

	// Test that system.read permission is required for both GetSystemInfo and GetMetrics
	userWithoutPermission := &interceptors.UserContext{
		UserID:      1,
		Username:    "user",
		Permissions: []string{"secrets.read", "secrets.write"}, // no system.read
	}

	// Create test user
	helper.CreateTestUser(t, userWithoutPermission.Username, userWithoutPermission.UserID)

	ctx := CreateSystemUserContext(userWithoutPermission)

	// Test GetSystemInfo
	_, err := service.GetSystemInfo(ctx, nil)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())

	// Test GetMetrics
	_, err = service.GetMetrics(ctx, nil)
	require.Error(t, err)
	st, ok = status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())
}

func TestSystemService_AuthenticationValidation(t *testing.T) {
	service := NewSystemService()
	ctx := context.Background() // No user context

	// Test GetSystemInfo
	_, err := service.GetSystemInfo(ctx, nil)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())

	// Test GetMetrics
	_, err = service.GetMetrics(ctx, nil)
	require.Error(t, err)
	st, ok = status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())

	// HealthCheck should work without authentication (but still returns Unimplemented)
	_, err = service.HealthCheck(ctx, nil)
	require.Error(t, err)
	st, ok = status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}