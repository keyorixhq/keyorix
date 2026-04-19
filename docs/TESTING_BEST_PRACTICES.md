# Testing Best Practices for Keyorix

## Overview

This document outlines the testing best practices, patterns, and guidelines for the Keyorix project. Following these practices ensures maintainable, reliable, and efficient tests that provide confidence in the codebase.

## Core Testing Principles

### 1. Test Pyramid Strategy

Follow the test pyramid approach:

```
    /\
   /  \     E2E Tests (Few)
  /____\    
 /      \   Integration Tests (Some)
/________\  Unit Tests (Many)
```

- **Unit Tests (70%)**: Test individual functions and methods in isolation
- **Integration Tests (20%)**: Test component interactions and workflows  
- **End-to-End Tests (10%)**: Test complete user scenarios

### 2. Test Independence

Each test should be completely independent:

```go
// ✅ Good: Independent test with its own setup
func TestCreateSecret(t *testing.T) {
    helper := testhelper.NewRBACTestHelper(t)
    defer helper.Cleanup()
    
    user := helper.CreateTestUser(t, "testuser", 1)
    // Test logic here
}

// ❌ Bad: Test depends on external state
var globalUser *models.User

func TestCreateSecret(t *testing.T) {
    // Assumes globalUser was set by another test
    secret := createSecret(globalUser.ID)
}
```

### 3. Clear Test Names

Use descriptive test names that explain the scenario:

```go
// ✅ Good: Clear, descriptive names
func TestCreateSecret_WithValidData_ReturnsSecret(t *testing.T) {}
func TestCreateSecret_WithInvalidUser_ReturnsError(t *testing.T) {}
func TestCreateSecret_WithInsufficientPermissions_ReturnsPermissionDenied(t *testing.T) {}

// ❌ Bad: Vague names
func TestCreateSecret1(t *testing.T) {}
func TestCreateSecret2(t *testing.T) {}
func TestError(t *testing.T) {}
```

## When to Use Mocks vs Real Components

### Use Real Components When:

1. **Testing Integration Points**: When you want to verify that components work together correctly
2. **Simple Dependencies**: When the dependency is lightweight and doesn't add complexity
3. **Database Operations**: Use in-memory databases for reliable, fast tests

```go
// ✅ Good: Using real core service with in-memory database
func TestSecretSharing_EndToEnd(t *testing.T) {
    helper := testhelper.NewRBACTestHelper(t)
    defer helper.Cleanup()
    
    // Create real users, roles, and secrets
    owner := helper.CreateTestUser(t, "owner", 1)
    recipient := helper.CreateTestUser(t, "recipient", 2)
    
    // Test the complete sharing workflow
    secret, err := helper.CoreService.CreateSecret(ctx, secretData)
    require.NoError(t, err)
    
    share, err := helper.CoreService.CreateShare(ctx, shareData)
    require.NoError(t, err)
    
    // Verify the recipient can access the secret
    retrievedSecret, err := helper.CoreService.GetSecret(recipientCtx, secret.ID)
    require.NoError(t, err)
    assert.Equal(t, secret.Name, retrievedSecret.Name)
}
```

### Use Mocks When:

1. **External Dependencies**: For external services, APIs, or slow operations
2. **Error Scenarios**: When you need to simulate specific error conditions
3. **Complex State Setup**: When setting up real state would be overly complex
4. **Unit Testing**: When testing a single component in isolation

```go
// ✅ Good: Using mocks for unit testing with specific error scenarios
func TestCreateSecret_StorageError_ReturnsError(t *testing.T) {
    mockStorage := &MockStorage{}
    coreService := core.NewKeyorixCore(mockStorage)
    
    // Mock a storage error
    mockStorage.On("CreateSecret", mock.Anything, mock.AnythingOfType("*models.SecretNode")).
        Return(nil, errors.New("database connection failed"))
    
    _, err := coreService.CreateSecret(ctx, secretData)
    
    require.Error(t, err)
    assert.Contains(t, err.Error(), "database connection failed")
    mockStorage.AssertExpectations(t)
}
```

## Mock Best Practices

### 1. Minimal Mock Expectations

Keep mock expectations simple and focused:

```go
// ✅ Good: Minimal, focused mock expectations
mockStorage.On("GetSecret", mock.Anything, uint(1)).
    Return(testSecret, nil)

// ❌ Bad: Overly complex mock chains
mockStorage.On("GetSecret", mock.Anything, uint(1)).
    Return(testSecret, nil).
    On("GetSecretVersions", mock.Anything, uint(1)).
    Return(versions, nil).
    On("CheckPermission", mock.Anything, uint(1), "secrets", "read").
    Return(true, nil)
```

### 2. Use Type-Safe Mock Arguments

Prefer specific types over `mock.Anything` when possible:

```go
// ✅ Good: Type-safe mock arguments
mockStorage.On("CreateSecret", mock.Anything, mock.AnythingOfType("*models.SecretNode")).
    Return(expectedSecret, nil)

// ✅ Better: Specific argument matching when needed
mockStorage.On("GetSecretByName", mock.Anything, "test-secret", uint(1), uint(1), uint(1)).
    Return(expectedSecret, nil)

// ❌ Avoid: Too generic
mockStorage.On("CreateSecret", mock.Anything, mock.Anything).
    Return(expectedSecret, nil)
```

### 3. Verify Mock Expectations

Always verify that mocks were called as expected:

```go
func TestWithMocks(t *testing.T) {
    mockStorage := &MockStorage{}
    // ... set up mocks and run test ...
    
    // Always verify expectations were met
    mockStorage.AssertExpectations(t)
}
```

## Test Structure Patterns

### 1. Arrange-Act-Assert (AAA) Pattern

Structure tests clearly with three sections:

```go
func TestCreateSecret_ValidInput_ReturnsSecret(t *testing.T) {
    // Arrange
    helper := testhelper.NewRBACTestHelper(t)
    defer helper.Cleanup()
    
    user := helper.CreateTestUser(t, "testuser", 1)
    helper.AssignUserRole(t, user.ID, 3, nil) // editor role
    
    secretData := &core.SecretData{
        Name:  "test-secret",
        Value: "secret-value",
        Type:  "password",
    }
    
    ctx := helper.CreateTestContext(user.ID, user.Username)
    
    // Act
    result, err := helper.CoreService.CreateSecret(ctx, secretData)
    
    // Assert
    require.NoError(t, err)
    assert.NotNil(t, result)
    assert.Equal(t, secretData.Name, result.Name)
    assert.NotZero(t, result.ID)
}
```

### 2. Table-Driven Tests for Multiple Scenarios

Use table-driven tests for comprehensive coverage:

```go
func TestSecretPermissions(t *testing.T) {
    helper := testhelper.NewRBACTestHelper(t)
    defer helper.Cleanup()
    
    tests := []struct {
        name           string
        userRole       string
        roleID         uint
        permission     string
        expectedResult bool
    }{
        {
            name:           "admin has all permissions",
            userRole:       "admin",
            roleID:         2,
            permission:     "secrets.delete",
            expectedResult: true,
        },
        {
            name:           "editor can read and write",
            userRole:       "editor", 
            roleID:         3,
            permission:     "secrets.write",
            expectedResult: true,
        },
        {
            name:           "editor cannot delete",
            userRole:       "editor",
            roleID:         3,
            permission:     "secrets.delete",
            expectedResult: false,
        },
        {
            name:           "viewer can only read",
            userRole:       "viewer",
            roleID:         4,
            permission:     "secrets.read",
            expectedResult: true,
        },
        {
            name:           "viewer cannot write",
            userRole:       "viewer",
            roleID:         4,
            permission:     "secrets.write",
            expectedResult: false,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Create user with specific role
            user := helper.CreateTestUser(t, tt.userRole+"_user", tt.roleID*10)
            helper.AssignUserRole(t, user.ID, tt.roleID, nil)
            
            // Test permission
            hasPermission := helper.HasPermission(t, user.ID, tt.permission)
            assert.Equal(t, tt.expectedResult, hasPermission)
        })
    }
}
```

### 3. Setup and Teardown Patterns

Use proper setup and teardown for resource management:

```go
// ✅ Good: Proper resource management
func TestComplexWorkflow(t *testing.T) {
    helper := testhelper.NewRBACTestHelper(t)
    defer helper.Cleanup() // Always defer cleanup
    
    // Test logic here
}

// ✅ Good: Custom setup function for complex scenarios
func setupComplexTestScenario(t *testing.T) (*testhelper.RBACTestHelper, *models.User, *models.Secret) {
    helper := testhelper.NewRBACTestHelper(t)
    
    user := helper.CreateTestUser(t, "testuser", 1)
    helper.AssignUserRole(t, user.ID, 3, nil) // editor role
    
    secret := helper.CreateTestSecret(t, "test-secret", user.ID, 1)
    
    return helper, user, secret
}

func TestComplexScenario(t *testing.T) {
    helper, user, secret := setupComplexTestScenario(t)
    defer helper.Cleanup()
    
    // Test logic using pre-configured scenario
}
```

## Error Testing Patterns

### 1. Test Expected Errors

Always test error conditions explicitly:

```go
func TestCreateSecret_DuplicateName_ReturnsError(t *testing.T) {
    helper := testhelper.NewRBACTestHelper(t)
    defer helper.Cleanup()
    
    user := helper.CreateTestUser(t, "testuser", 1)
    ctx := helper.CreateTestContext(user.ID, user.Username)
    
    // Create first secret
    _, err := helper.CoreService.CreateSecret(ctx, &core.SecretData{
        Name: "duplicate-name",
        Value: "value1",
    })
    require.NoError(t, err)
    
    // Attempt to create duplicate
    _, err = helper.CoreService.CreateSecret(ctx, &core.SecretData{
        Name: "duplicate-name",
        Value: "value2",
    })
    
    // Verify specific error
    require.Error(t, err)
    assert.Contains(t, err.Error(), "already exists")
}
```

### 2. Test Error Types

Use error type checking for specific error conditions:

```go
func TestGetSecret_NotFound_ReturnsNotFoundError(t *testing.T) {
    mockStorage := &MockStorage{}
    coreService := core.NewKeyorixCore(mockStorage)
    
    mockStorage.On("GetSecret", mock.Anything, uint(999)).
        Return(nil, storage.ErrSecretNotFound)
    
    _, err := coreService.GetSecret(ctx, 999)
    
    require.Error(t, err)
    assert.ErrorIs(t, err, core.ErrSecretNotFound)
}
```

### 3. gRPC Error Code Testing

For gRPC services, test specific error codes:

```go
func TestGRPCService_Unauthenticated_ReturnsUnauthenticatedError(t *testing.T) {
    helper := NewTestHelper(t)
    service := &SecretGRPCService{secretService: helper.CoreService}
    
    // Call without authentication context
    _, err := service.GetSecret(context.Background(), &GetSecretRequest{Id: 1})
    
    require.Error(t, err)
    st, ok := status.FromError(err)
    require.True(t, ok)
    assert.Equal(t, codes.Unauthenticated, st.Code())
}
```

## Performance Testing Patterns

### 1. Benchmark Tests

Write benchmark tests for performance-critical code:

```go
func BenchmarkSecretEncryption(b *testing.B) {
    encryptionService := encryption.NewService()
    data := []byte("test secret data")
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := encryptionService.Encrypt(data)
        if err != nil {
            b.Fatal(err)
        }
    }
}

func BenchmarkSecretListing(b *testing.B) {
    helper := testhelper.NewRBACTestHelper(b)
    defer helper.Cleanup()
    
    // Create test data
    user := helper.CreateTestUser(b, "testuser", 1)
    for i := 0; i < 1000; i++ {
        helper.CreateTestSecret(b, fmt.Sprintf("secret-%d", i), user.ID, uint(i+1))
    }
    
    ctx := helper.CreateTestContext(user.ID, user.Username)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, _, err := helper.CoreService.ListSecrets(ctx, &core.SecretFilter{
            Page:     1,
            PageSize: 50,
        })
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

### 2. Load Testing Patterns

For testing under load conditions:

```go
func TestConcurrentSecretAccess(t *testing.T) {
    helper := testhelper.NewRBACTestHelper(t)
    defer helper.Cleanup()
    
    user := helper.CreateTestUser(t, "testuser", 1)
    secret := helper.CreateTestSecret(t, "shared-secret", user.ID, 1)
    ctx := helper.CreateTestContext(user.ID, user.Username)
    
    // Test concurrent access
    const numGoroutines = 10
    const numRequests = 100
    
    var wg sync.WaitGroup
    errors := make(chan error, numGoroutines*numRequests)
    
    for i := 0; i < numGoroutines; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for j := 0; j < numRequests; j++ {
                _, err := helper.CoreService.GetSecret(ctx, secret.ID)
                if err != nil {
                    errors <- err
                }
            }
        }()
    }
    
    wg.Wait()
    close(errors)
    
    // Check for errors
    for err := range errors {
        t.Errorf("Concurrent access error: %v", err)
    }
}
```

## Test Organization

### 1. File Organization

Organize test files consistently:

```
internal/
├── core/
│   ├── service.go
│   ├── service_test.go          # Unit tests
│   ├── integration_test.go      # Integration tests
│   └── benchmark_test.go        # Performance tests
├── server/
│   ├── grpc/
│   │   ├── services/
│   │   │   ├── secret_service.go
│   │   │   ├── secret_service_test.go      # gRPC service tests
│   │   │   └── secret_service_simple_test.go  # Basic functionality tests
```

### 2. Test Naming Conventions

Follow consistent naming patterns:

```go
// Unit tests: TestFunctionName_Scenario_ExpectedResult
func TestCreateSecret_ValidInput_ReturnsSecret(t *testing.T) {}
func TestCreateSecret_InvalidInput_ReturnsError(t *testing.T) {}

// Integration tests: TestIntegration_Workflow_ExpectedResult  
func TestIntegration_SecretSharing_SharesSuccessfully(t *testing.T) {}

// Benchmark tests: BenchmarkFunctionName_Scenario
func BenchmarkCreateSecret_LargePayload(b *testing.B) {}
```

### 3. Test Tags

Use build tags for different test types:

```go
//go:build integration
// +build integration

package core

// Integration tests that require database setup
func TestIntegration_CompleteWorkflow(t *testing.T) {
    // Integration test logic
}
```

```bash
# Run only unit tests
go test ./...

# Run integration tests
go test -tags=integration ./...

# Run benchmarks
go test -bench=. ./...
```

## Common Anti-Patterns to Avoid

### 1. Shared Test State

```go
// ❌ Bad: Shared state between tests
var testUser *models.User

func TestA(t *testing.T) {
    testUser = createUser("test")
    // test logic
}

func TestB(t *testing.T) {
    // Depends on TestA running first
    secret := createSecret(testUser.ID)
}

// ✅ Good: Independent test setup
func TestA(t *testing.T) {
    user := createUser("test")
    // test logic with local user
}

func TestB(t *testing.T) {
    user := createUser("test")
    secret := createSecret(user.ID)
    // test logic
}
```

### 2. Testing Implementation Details

```go
// ❌ Bad: Testing internal implementation
func TestCreateSecret_CallsStorageCreateSecret(t *testing.T) {
    mockStorage := &MockStorage{}
    service := core.NewKeyorixCore(mockStorage)
    
    mockStorage.On("CreateSecret", mock.Anything, mock.Anything).Return(nil, nil)
    
    service.CreateSecret(ctx, data)
    
    // Only testing that storage was called, not the actual behavior
    mockStorage.AssertExpectations(t)
}

// ✅ Good: Testing behavior and outcomes
func TestCreateSecret_ValidInput_ReturnsCreatedSecret(t *testing.T) {
    helper := testhelper.NewRBACTestHelper(t)
    defer helper.Cleanup()
    
    user := helper.CreateTestUser(t, "testuser", 1)
    ctx := helper.CreateTestContext(user.ID, user.Username)
    
    result, err := helper.CoreService.CreateSecret(ctx, secretData)
    
    require.NoError(t, err)
    assert.Equal(t, secretData.Name, result.Name)
    assert.NotZero(t, result.ID)
    
    // Verify the secret was actually created
    retrieved, err := helper.CoreService.GetSecret(ctx, result.ID)
    require.NoError(t, err)
    assert.Equal(t, result.Name, retrieved.Name)
}
```

### 3. Overly Complex Test Setup

```go
// ❌ Bad: Overly complex setup
func TestComplexScenario(t *testing.T) {
    // 50 lines of setup code
    db := setupDatabase()
    user1 := createUser("user1")
    user2 := createUser("user2")
    role1 := createRole("role1")
    // ... many more setup steps
    
    // Actual test is buried in complexity
    result := doSomething()
    assert.True(t, result)
}

// ✅ Good: Use helper functions for complex setup
func TestComplexScenario(t *testing.T) {
    scenario := setupComplexTestScenario(t)
    defer scenario.Cleanup()
    
    result := scenario.DoSomething()
    assert.True(t, result)
}

func setupComplexTestScenario(t *testing.T) *TestScenario {
    // Complex setup logic encapsulated in helper
    // Returns a structured scenario object
}
```

## Test Maintenance

### 1. Keep Tests Up to Date

- Update tests when APIs change
- Remove obsolete tests for removed features
- Refactor tests when code structure changes

### 2. Test Documentation

Document complex test scenarios:

```go
// TestSecretSharing_GroupPermissions tests the complete group-based secret sharing workflow.
// This test verifies that:
// 1. A user can share a secret with a group
// 2. All group members can access the shared secret
// 3. Users not in the group cannot access the secret
// 4. Group permissions are properly enforced
func TestSecretSharing_GroupPermissions(t *testing.T) {
    // Test implementation
}
```

### 3. Regular Test Review

- Review test coverage regularly
- Identify and fix flaky tests
- Optimize slow tests
- Remove redundant tests

## Conclusion

Following these testing best practices ensures:

- **Reliability**: Tests consistently pass and catch regressions
- **Maintainability**: Tests are easy to understand and modify
- **Efficiency**: Tests run quickly and provide fast feedback
- **Confidence**: Comprehensive coverage gives confidence in deployments

Remember: Good tests are an investment in code quality and developer productivity. They should be treated as first-class citizens in the codebase.