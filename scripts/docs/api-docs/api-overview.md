# API Documentation Overview

## Introduction
The Keyorix API provides programmatic access to all secret management functionality. The API follows REST principles and uses JSON for data exchange.

## Base URL
```
Production: https://your-domain.com/api/v1
Development: https://localhost/api/v1
```

## Authentication
All API requests require authentication using JWT tokens.

### Getting an API Token
1. **Web Dashboard Method**:
   - Go to Profile → API Keys
   - Click "Generate New Key"
   - Copy the token (shown only once)

2. **CLI Method**:
   ```bash
   keyorix auth token create --name "my-api-key"
   ```

### Using the Token
Include the token in the Authorization header:
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     https://localhost/api/v1/secrets
```

## API Endpoints

### Authentication Endpoints
- `POST /auth/login` - User login
- `POST /auth/logout` - User logout
- `POST /auth/refresh` - Refresh JWT token
- `GET /auth/me` - Get current user info

### Secret Management
- `GET /secrets` - List secrets
- `POST /secrets` - Create secret
- `GET /secrets/{id}` - Get secret details
- `PUT /secrets/{id}` - Update secret
- `DELETE /secrets/{id}` - Delete secret
- `GET /secrets/{id}/history` - Get version history

### Sharing Management
- `GET /shares` - List shares
- `POST /shares` - Create share
- `GET /shares/{id}` - Get share details
- `PUT /shares/{id}` - Update share
- `DELETE /shares/{id}` - Delete share
- `POST /shares/{id}/accept` - Accept share invitation

### User Management
- `GET /users` - List users (admin only)
- `POST /users` - Create user (admin only)
- `GET /users/{id}` - Get user details
- `PUT /users/{id}` - Update user
- `DELETE /users/{id}` - Delete user (admin only)

### System Endpoints
- `GET /health` - System health check
- `GET /metrics` - System metrics (admin only)
- `GET /audit` - Audit logs (admin only)

## Response Format
All API responses follow this format:
```json
{
  "success": true,
  "data": { ... },
  "message": "Operation completed successfully",
  "timestamp": "2025-01-31T12:00:00Z"
}
```

Error responses:
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": { ... }
  },
  "timestamp": "2025-01-31T12:00:00Z"
}
```

## Rate Limiting
- **Standard Users**: 100 requests per minute
- **Premium Users**: 1000 requests per minute
- **Admin Users**: 5000 requests per minute

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1643723400
```

## Error Codes
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `409` - Conflict
- `422` - Validation Error
- `429` - Rate Limited
- `500` - Internal Server Error

## Interactive Documentation
Visit https://localhost/swagger/ for interactive API documentation with:
- Live API testing
- Request/response examples
- Schema definitions
- Authentication testing
