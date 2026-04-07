# HTTP/gRPC Server Testing Guide

## 🧪 Overview

This guide covers comprehensive testing for the Keyorix HTTP and gRPC server implementation. The test suite includes unit tests, integration tests, performance benchmarks, and security tests.

## 📋 Test Coverage

### ✅ HTTP Server Tests

#### 1. **Handler Tests** (`server/http/handlers/*_test.go`)
- **Secrets Handler** (`secrets_test.go`)
  - ✅ List secrets with pagination and filtering
  - ✅ Create secret with validation
  - ✅ Get secret by ID
  - ✅ Update secret
  - ✅ Delete secret
  - ✅ Get secret versions
  - ✅ Authentication and authorization checks
  - ✅ Error handling and validation

- **RBAC Handler** (`rbac_test.go`)
  - ✅ User management (CRUD operations)
  - ✅ Role management (CRUD operations)
  - ✅ Role assignment and removal
  - ✅ Permission checking
  - ✅ Input validation

- **System Handler** (`system_test.go`)
  - ✅ Health check endpoint
  - ✅ System information retrieval
  - ✅ Metrics collection
  - ✅ Concurrent access testing
  - ✅ Performance benchmarks

- **Audit Handler** (`audit_test.go`)
  - ✅ Audit log retrieval with filtering
  - ✅ RBAC audit logs
  - ✅ Query parameter parsing
  - ✅ Data consistency validation

#### 2. **Integration Tests** (`server/http/integration_test.go`)
- ✅ Complete secret management workflow
- ✅ RBAC management workflow
- ✅ System information endpoints
- ✅ Error scenario testing
- ✅ Performance and load testing
- ✅ Concurrent request handling

### ✅ gRPC Server Tests

#### 1. **Service Tests** (`server/grpc/services/*_test.go`)
- **Secret Service** (`secret_service_test.go`)
  - ✅ CreateSecret with validation
  - ✅ GetSecret with permissions
  - ✅ ListSecrets with filtering
  - ✅ UpdateSecret operations
  - ✅ DeleteSecret operations
  - ✅ Permission validation
  - ✅ Error code mapping
  - ✅ Performance benchmarks

### ✅ Middleware Tests

#### 1. **Authentication Tests** (`server/middleware/auth_test.go`)
- ✅ JWT token validation
- ✅ User context extraction
- ✅ Permission checking
- ✅ Role-based access control
- ✅ Middleware chaining
- ✅ Concurrent access
- ✅ Performance benchmarks

## 🚀 Running Tests

### Quick Start

```bash
# Navigate to server directory
cd server

# Run all tests
go run test_runner.go all

# Run specific test suite
go test ./http/handlers -v
go test ./grpc/services -v
go test ./middleware -v

# Run integration tests
go test ./http -v
```

### Using the Test Runner

The test runner provides a comprehensive testing interface:

```bash
# Run all test suites
go run test_runner.go all

# Run performance benchmarks
go run test_runner.go bench

# Generate coverage report
go run test_runner.go coverage

# Show help
go run test_runner.go help
```

### Manual Test Commands

```bash
# Unit tests with coverage
go test -v -race -cover ./...

# Run specific test
go test -v -run TestSecretHandler_CreateSecret ./http/handlers

# Run benchmarks
go test -bench=. -benchmem ./http/handlers

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

## 📊 Test Categories

### 1. **Unit Tests**
- Test individual functions and methods
- Mock external dependencies
- Focus on business logic validation
- Fast execution (< 1 second per test)

### 2. **Integration Tests**
- Test complete workflows end-to-end
- Use real HTTP server instances
- Test middleware interactions
- Validate API contracts

### 3. **Performance Tests**
- Benchmark critical operations
- Concurrent request handling
- Memory usage validation
- Response time measurements

### 4. **Security Tests**
- Authentication bypass attempts
- Authorization validation
- Input validation and sanitization
- Error information leakage prevention

## 🔧 Test Configuration

### Authentication Tokens for Testing

The test suite uses mock JWT tokens:

```go
// Admin token with full permissions
"valid-token" -> UserContext{
    UserID: 1,
    Username: "admin",
    Permissions: ["secrets.read", "secrets.write", "secrets.delete", ...]
}

// Limited user token
"test-token" -> UserContext{
    UserID: 2,
    Username: "testuser", 
    Permissions: ["secrets.read", "users.read"]
}
```

### Test Data

Tests use mock data that simulates real scenarios:
- Secrets with various types and metadata
- Users with different roles and permissions
- Audit logs with realistic timestamps
- System metrics with actual runtime data

## 📈 Coverage Goals

| Component | Target Coverage | Current Status |
|-----------|----------------|----------------|
| HTTP Handlers | 90%+ | ✅ Achieved |
| gRPC Services | 85%+ | ✅ Achieved |
| Middleware | 95%+ | ✅ Achieved |
| Integration | 80%+ | ✅ Achieved |

## 🧩 Test Structure

### Test File Organization

```
server/
├── http/
│   ├── handlers/
│   │   ├── secrets_test.go      # Secret endpoint tests
│   │   ├── rbac_test.go         # RBAC endpoint tests
│   │   ├── system_test.go       # System endpoint tests
│   │   └── audit_test.go        # Audit endpoint tests
│   └── integration_test.go      # End-to-end integration tests
├── grpc/
│   └── services/
│       └── secret_service_test.go # gRPC service tests
├── middleware/
│   └── auth_test.go             # Authentication middleware tests
└── test_runner.go               # Comprehensive test runner
```

### Test Naming Convention

```go
// Function tests
func TestSecretHandler_CreateSecret(t *testing.T)
func TestAuthentication(t *testing.T)

// Benchmark tests  
func BenchmarkSecretHandler_ListSecrets(b *testing.B)
func BenchmarkAuthentication(b *testing.B)

// Integration tests
func TestHTTPServerIntegration(t *testing.T)
func TestHTTPServerErrorScenarios(t *testing.T)
```

## 🔍 Test Scenarios

### 1. **Happy Path Tests**
- Valid requests with proper authentication
- Successful CRUD operations
- Proper response formats
- Expected status codes

### 2. **Error Path Tests**
- Invalid authentication tokens
- Insufficient permissions
- Malformed request data
- Non-existent resources
- Server errors

### 3. **Edge Case Tests**
- Empty request bodies
- Maximum field lengths
- Boundary value testing
- Concurrent operations
- Race conditions

### 4. **Security Tests**
- Authentication bypass attempts
- Permission escalation attempts
- Input injection testing
- Information disclosure prevention

## 📋 Test Checklist

### Before Running Tests

- [ ] Ensure Go 1.19+ is installed
- [ ] All dependencies are available (`go mod tidy`)
- [ ] No conflicting processes on test ports
- [ ] Sufficient system resources available

### Test Execution Checklist

- [ ] All unit tests pass
- [ ] Integration tests pass
- [ ] No race conditions detected
- [ ] Coverage targets met
- [ ] Benchmarks within acceptable ranges
- [ ] No memory leaks detected

### After Testing

- [ ] Review coverage report
- [ ] Analyze benchmark results
- [ ] Check for any flaky tests
- [ ] Update documentation if needed

## 🚨 Troubleshooting

### Common Issues

**Tests fail with "address already in use"**
```bash
# Check for processes using test ports
lsof -i :8080
lsof -i :9090

# Kill conflicting processes
kill -9 <PID>
```

**Race condition detected**
```bash
# Run with race detection
go test -race ./...

# Fix any reported race conditions
```

**Coverage too low**
```bash
# Generate detailed coverage report
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# Identify untested code
go tool cover -html=coverage.out
```

**Benchmark performance issues**
```bash
# Run benchmarks with memory profiling
go test -bench=. -benchmem -memprofile=mem.prof ./...

# Analyze memory usage
go tool pprof mem.prof
```

## 📊 Performance Benchmarks

### Expected Performance Targets

| Operation | Target | Measurement |
|-----------|--------|-------------|
| Health Check | < 1ms | Response time |
| List Secrets | < 10ms | Response time |
| Create Secret | < 50ms | Response time |
| Authentication | < 5ms | Middleware overhead |
| Concurrent Requests | 1000+ req/s | Throughput |

### Running Benchmarks

```bash
# Run all benchmarks
go run test_runner.go bench

# Run specific benchmarks
go test -bench=BenchmarkSecretHandler ./http/handlers
go test -bench=BenchmarkAuthentication ./middleware

# With memory profiling
go test -bench=. -benchmem ./...
```

## 🎯 Continuous Integration

### GitHub Actions Integration

```yaml
name: Test Suite
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v3
        with:
          go-version: '1.19'
      - name: Run Tests
        run: |
          cd server
          go run test_runner.go all
      - name: Generate Coverage
        run: |
          cd server  
          go run test_runner.go coverage
```

## 📝 Writing New Tests

### Test Template

```go
func TestNewFeature(t *testing.T) {
    tests := []struct {
        name           string
        input          interface{}
        expectedOutput interface{}
        expectedError  string
    }{
        {
            name:           "successful case",
            input:          validInput,
            expectedOutput: expectedResult,
            expectedError:  "",
        },
        {
            name:          "error case",
            input:         invalidInput,
            expectedError: "expected error message",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
            result, err := functionUnderTest(tt.input)
            
            if tt.expectedError != "" {
                assert.Error(t, err)
                assert.Contains(t, err.Error(), tt.expectedError)
            } else {
                assert.NoError(t, err)
                assert.Equal(t, tt.expectedOutput, result)
            }
        })
    }
}
```

## 🎉 Summary

The HTTP and gRPC server implementation includes comprehensive testing covering:

✅ **Complete Test Coverage**: Unit, integration, performance, and security tests  
✅ **Automated Test Runner**: Easy-to-use test execution and reporting  
✅ **Performance Benchmarks**: Ensuring optimal server performance  
✅ **Security Validation**: Authentication, authorization, and input validation  
✅ **CI/CD Ready**: Structured for continuous integration pipelines  

The test suite ensures the server implementation is production-ready, secure, and performant! 🚀