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

// TestHelper provides consistent test setup for secret service tests
type TestHelper struct {
	CoreService *core.KeyorixCore
	DB          *gorm.DB
}

// NewTestHelper creates a new test helper with in-memory database and core service
func NewTestHelper(t *testing.T) *TestHelper {
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

	return &TestHelper{
		CoreService: coreService,
		DB:          db,
	}
}

// CreateTestUser creates a test user in the database
func (h *TestHelper) CreateTestUser(t *testing.T, username string, userID uint) *models.User {
	user := &models.User{
		ID:       userID,
		Username: username,
	}
	err := h.DB.Create(user).Error
	require.NoError(t, err)
	return user
}

// CreateUserContext creates a context with user information for testing
func CreateUserContext(userCtx *interceptors.UserContext) context.Context {
	if userCtx == nil {
		return context.Background()
	}
	return context.WithValue(context.Background(), interceptors.GetUserContextKey(), userCtx)
}

func TestSecretServiceCreation(t *testing.T) {
	helper := NewTestHelper(t)

	// Create secret service with core service
	service := &SecretGRPCService{
		secretService: helper.CoreService,
	}

	assert.NotNil(t, service)
	assert.NotNil(t, service.secretService)
}

func TestSecretServiceCreateSecret(t *testing.T) {
	helper := NewTestHelper(t)
	
	// Create test user
	helper.CreateTestUser(t, "testuser", 1)

	// Create secret service
	service := &SecretGRPCService{
		secretService: helper.CoreService,
	}

	tests := []struct {
		name           string
		userCtx        *interceptors.UserContext
		request        *CreateSecretRequest
		expectedError  codes.Code
		expectResponse bool
	}{
		{
			name: "successful creation with valid user",
			userCtx: &interceptors.UserContext{
				UserID:      1,
				Username:    "testuser",
				Permissions: []string{"secrets.write"},
			},
			request: &CreateSecretRequest{
				Name:        "test-secret",
				Value:       "secret-value",
				Namespace:   "default",
				Zone:        "us-east-1",
				Environment: "dev",
				Type:        "password",
				Metadata:    map[string]string{"owner": "test-user"},
				Tags:        []string{"test", "development"},
			},
			expectedError:  codes.OK,
			expectResponse: true,
		},
		{
			name:           "unauthenticated user",
			userCtx:        nil,
			request:        &CreateSecretRequest{},
			expectedError:  codes.Unauthenticated,
			expectResponse: false,
		},
		{
			name: "insufficient permissions",
			userCtx: &interceptors.UserContext{
				UserID:      1,
				Username:    "testuser",
				Permissions: []string{"secrets.read"}, // missing secrets.write
			},
			request: &CreateSecretRequest{
				Name:        "test-secret",
				Value:       "secret-value",
				Namespace:   "default",
				Zone:        "us-east-1",
				Environment: "dev",
			},
			expectedError:  codes.PermissionDenied,
			expectResponse: false,
		},
		{
			name: "missing required fields",
			userCtx: &interceptors.UserContext{
				UserID:      1,
				Username:    "testuser",
				Permissions: []string{"secrets.write"},
			},
			request: &CreateSecretRequest{
				Name:  "", // missing name
				Value: "secret-value",
			},
			expectedError:  codes.InvalidArgument,
			expectResponse: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create context with user
			ctx := CreateUserContext(tt.userCtx)

			// Call service method
			response, err := service.CreateSecret(ctx, tt.request)

			// Check error code
			if tt.expectedError != codes.OK {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.expectedError, st.Code())
				assert.Nil(t, response)
			} else {
				require.NoError(t, err)
				if tt.expectResponse {
					require.NotNil(t, response)
					assert.NotZero(t, response.Id)
					assert.Equal(t, tt.request.Name, response.Name)
				}
			}
		})
	}
}

func TestSecretServiceGetSecret(t *testing.T) {
	helper := NewTestHelper(t)
	
	// Create test user
	helper.CreateTestUser(t, "testuser", 1)

	// Create secret service
	service := &SecretGRPCService{
		secretService: helper.CoreService,
	}

	tests := []struct {
		name           string
		userCtx        *interceptors.UserContext
		request        *GetSecretRequest
		expectedError  codes.Code
		expectResponse bool
	}{
		{
			name:           "unauthenticated user",
			userCtx:        nil,
			request:        &GetSecretRequest{Id: 1},
			expectedError:  codes.Unauthenticated,
			expectResponse: false,
		},
		{
			name: "insufficient permissions",
			userCtx: &interceptors.UserContext{
				UserID:      1,
				Username:    "testuser",
				Permissions: []string{"users.read"}, // missing secrets.read
			},
			request:        &GetSecretRequest{Id: 1},
			expectedError:  codes.PermissionDenied,
			expectResponse: false,
		},
		{
			name: "secret not found",
			userCtx: &interceptors.UserContext{
				UserID:      1,
				Username:    "testuser",
				Permissions: []string{"secrets.read"},
			},
			request:        &GetSecretRequest{Id: 99999},
			expectedError:  codes.NotFound,
			expectResponse: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create context with user
			ctx := CreateUserContext(tt.userCtx)

			// Call service method
			response, err := service.GetSecret(ctx, tt.request)

			// Check error code
			if tt.expectedError != codes.OK {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.expectedError, st.Code())
				assert.Nil(t, response)
			} else {
				require.NoError(t, err)
				if tt.expectResponse {
					require.NotNil(t, response)
					assert.Equal(t, tt.request.Id, response.Id)
					assert.NotEmpty(t, response.Name)
				}
			}
		})
	}
}

func TestSecretServiceListSecrets(t *testing.T) {
	helper := NewTestHelper(t)
	
	// Create test user
	helper.CreateTestUser(t, "testuser", 1)

	// Create secret service
	service := &SecretGRPCService{
		secretService: helper.CoreService,
	}

	tests := []struct {
		name           string
		userCtx        *interceptors.UserContext
		request        *ListSecretsRequest
		expectedError  codes.Code
		expectResponse bool
	}{
		{
			name: "successful list with valid user",
			userCtx: &interceptors.UserContext{
				UserID:      1,
				Username:    "testuser",
				Permissions: []string{"secrets.read"},
			},
			request: &ListSecretsRequest{
				Page:     1,
				PageSize: 20,
			},
			expectedError:  codes.OK,
			expectResponse: true,
		},
		{
			name:           "unauthenticated user",
			userCtx:        nil,
			request:        &ListSecretsRequest{},
			expectedError:  codes.Unauthenticated,
			expectResponse: false,
		},
		{
			name: "insufficient permissions",
			userCtx: &interceptors.UserContext{
				UserID:      1,
				Username:    "testuser",
				Permissions: []string{"users.read"}, // missing secrets.read
			},
			request:        &ListSecretsRequest{},
			expectedError:  codes.PermissionDenied,
			expectResponse: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create context with user
			ctx := CreateUserContext(tt.userCtx)

			// Call service method
			response, err := service.ListSecrets(ctx, tt.request)

			// Check error code
			if tt.expectedError != codes.OK {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.expectedError, st.Code())
				assert.Nil(t, response)
			} else {
				require.NoError(t, err)
				if tt.expectResponse {
					require.NotNil(t, response)
					assert.NotNil(t, response.Secrets)
					assert.GreaterOrEqual(t, response.Total, int64(0))
				}
			}
		})
	}
}