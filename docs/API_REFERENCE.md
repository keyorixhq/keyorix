# 🔌 Keyorix API Reference

Complete API documentation for the Keyorix secret management system.

## 📊 **API Status**
- **Status**: Production Ready ✅
- **Version**: 1.0.0
- **Base URL**: `http://localhost:8080`
- **Authentication**: Bearer Token Required
- **Response Format**: JSON
- **OpenAPI Spec**: Available at `/openapi.yaml`

## 🌐 **Base Endpoints**

### Health Check
```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-10-08T14:17:46.801479Z",
  "uptime": "5m0.000001541s",
  "version": "1.0.0",
  "checks": {
    "database": {
      "status": "healthy",
      "latency": "2ms"
    },
    "encryption": {
      "status": "healthy",
      "provider": "AES-256-GCM"
    },
    "storage": {
      "status": "healthy",
      "free_space": "85%"
    }
  }
}
```

### OpenAPI Specification
```http
GET /openapi.yaml
```

Returns the complete OpenAPI 3.0 specification for all endpoints.

## 🔐 **Secret Management API**

### List Secrets
```http
GET /api/v1/secrets
Authorization: Bearer <token>
```

**Query Parameters:**
- `limit` (int): Number of secrets to return (default: 50)
- `offset` (int): Number of secrets to skip (default: 0)
- `namespace` (int): Namespace ID filter (default: 1)
- `zone` (int): Zone ID filter (default: 1)
- `environment` (int): Environment ID filter (default: 1)

**Response:**
```json
{
  "secrets": [
    {
      "id": 1,
      "name": "example-api-key",
      "type": "api-key-v2",
      "status": "active",
      "namespace_id": 1,
      "zone_id": 1,
      "environment_id": 1,
      "created_by": "example-user",
      "created_at": "2025-07-17T00:42:01+03:00",
      "updated_at": "2025-07-17T00:42:01+03:00",
      "expires_at": null
    }
  ],
  "total": 14,
  "limit": 50,
  "offset": 0
}
```

### Create Secret
```http
POST /api/v1/secrets
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "name": "my-api-key",
  "value": "secret-value-here",
  "type": "api_key",
  "namespace_id": 1,
  "zone_id": 1,
  "environment_id": 1,
  "expires_at": "2025-12-31T23:59:59Z",
  "max_reads": 0
}
```

**Response:**
```json
{
  "id": 15,
  "name": "my-api-key",
  "type": "api_key",
  "status": "active",
  "namespace_id": 1,
  "zone_id": 1,
  "environment_id": 1,
  "created_by": "current-user",
  "created_at": "2025-10-08T16:30:00Z",
  "updated_at": "2025-10-08T16:30:00Z"
}
```

### Get Secret
```http
GET /api/v1/secrets/{id}
Authorization: Bearer <token>
```

**Query Parameters:**
- `show_value` (bool): Include decrypted value in response (default: false)

**Response:**
```json
{
  "id": 1,
  "name": "example-api-key",
  "type": "api-key-v2",
  "status": "active",
  "namespace_id": 1,
  "zone_id": 1,
  "environment_id": 1,
  "created_by": "example-user",
  "created_at": "2025-07-17T00:42:01+03:00",
  "updated_at": "2025-07-17T00:42:01+03:00",
  "value": "decrypted-secret-value"
}
```

### Update Secret
```http
PUT /api/v1/secrets/{id}
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "value": "new-secret-value",
  "type": "updated-type",
  "expires_at": "2025-12-31T23:59:59Z"
}
```

### Delete Secret
```http
DELETE /api/v1/secrets/{id}
Authorization: Bearer <token>
```

**Response:**
```json
{
  "message": "Secret deleted successfully",
  "id": 1
}
```

## 🤝 **Secret Sharing API**

### Create Share
```http
POST /api/v1/shares
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "secret_id": 1,
  "recipient_id": 2,
  "permission": "read",
  "is_group": false,
  "expires_at": "2025-12-31T23:59:59Z"
}
```

### List Shares
```http
GET /api/v1/shares
Authorization: Bearer <token>
```

**Query Parameters:**
- `secret_id` (int): Filter by secret ID
- `recipient_id` (int): Filter by recipient ID
- `is_group` (bool): Filter by group shares

### Update Share
```http
PUT /api/v1/shares/{id}
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "permission": "write",
  "expires_at": "2025-12-31T23:59:59Z"
}
```

### Delete Share
```http
DELETE /api/v1/shares/{id}
Authorization: Bearer <token>
```

## 👥 **User Management API**

### List Users
```http
GET /api/v1/users
Authorization: Bearer <token>
```

### Create User
```http
POST /api/v1/users
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "username": "newuser",
  "email": "user@example.com",
  "role": "user"
}
```

## 🔧 **System API**

### System Information
```http
GET /api/v1/system/info
Authorization: Bearer <token>
```

**Response:**
```json
{
  "version": "1.0.0",
  "build_time": "2025-10-08T14:00:00Z",
  "go_version": "go1.21.0",
  "storage_type": "local",
  "encryption_enabled": true,
  "languages_supported": ["en", "ru", "es", "fr", "de"]
}
```

### System Metrics
```http
GET /api/v1/system/metrics
Authorization: Bearer <token>
```

**Response:**
```json
{
  "secrets_count": 14,
  "users_count": 5,
  "shares_count": 3,
  "database_size": "2.5MB",
  "uptime": "5h30m",
  "memory_usage": "45MB",
  "cpu_usage": "2.1%"
}
```

## 🔐 **Authentication**

### Login
```http
POST /api/v1/auth/login
Content-Type: application/json
```

**Request Body:**
```json
{
  "username": "user@example.com",
  "password": "secure-password"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2025-10-09T16:30:00Z",
  "user": {
    "id": 1,
    "username": "user@example.com",
    "role": "user"
  }
}
```

### Refresh Token
```http
POST /api/v1/auth/refresh
Authorization: Bearer <token>
```

### Logout
```http
POST /api/v1/auth/logout
Authorization: Bearer <token>
```

## 📝 **Error Responses**

All API endpoints return consistent error responses:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Secret name is required",
    "details": {
      "field": "name",
      "value": "",
      "constraint": "required"
    }
  },
  "timestamp": "2025-10-08T16:30:00Z",
  "path": "/api/v1/secrets"
}
```

### Common Error Codes
- `VALIDATION_ERROR` - Invalid request data
- `AUTHENTICATION_REQUIRED` - Missing or invalid token
- `PERMISSION_DENIED` - Insufficient permissions
- `RESOURCE_NOT_FOUND` - Requested resource doesn't exist
- `RESOURCE_ALREADY_EXISTS` - Resource with same identifier exists
- `INTERNAL_ERROR` - Server-side error

## 🌍 **Multi-Language Support**

All API responses support internationalization via the `Accept-Language` header:

```http
GET /api/v1/secrets
Authorization: Bearer <token>
Accept-Language: ru
```

Supported languages:
- `en` - English (default)
- `ru` - Russian
- `es` - Spanish
- `fr` - French
- `de` - German

## 📊 **Rate Limiting**

API endpoints are rate-limited to prevent abuse:

- **Default**: 100 requests per minute per user
- **Authentication**: 10 requests per minute per IP
- **Headers**: Rate limit information included in responses

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1696780800
```

## 🔌 **gRPC API**

For high-performance integrations, Keyorix also provides gRPC endpoints:

- **Port**: 9090 (default)
- **Services**: SecretService, ShareService, SystemService
- **Protocol Buffers**: Available in `/proto` directory

### Example gRPC Usage
```go
conn, err := grpc.Dial("localhost:9090", grpc.WithInsecure())
client := pb.NewSecretServiceClient(conn)

response, err := client.ListSecrets(ctx, &pb.ListSecretsRequest{
    Limit: 10,
    Offset: 0,
})
```

## 📚 **Additional Resources**

- **OpenAPI Spec**: `GET /openapi.yaml`
- **Swagger UI**: `http://localhost:8080/swagger/` (if enabled)
- **Health Check**: `GET /health`
- **System Status**: Available via CLI `./keyorix status`

## 🚀 **Getting Started**

1. **Start the server**: `./keyorix-server`
2. **Check health**: `curl http://localhost:8080/health`
3. **Get OpenAPI spec**: `curl http://localhost:8080/openapi.yaml`
4. **Create your first secret**: Use the CLI or API endpoints above

Your Keyorix API is production-ready and fully documented!