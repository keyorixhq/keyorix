# 🔌 Keyorix API Reference

Complete API documentation for the Keyorix secret management system.

## 📊 **API Status**
- **Status**: Production Ready ✅
- **Version**: 1.0.0
- **Base URL**: `http://localhost:8080`
- **Authentication**: Bearer Token Required
- **Response Format**: JSON
- **OpenAPI Spec**: Available at `/openapi.yaml`

> **Response envelope:** every success response below is actually wrapped as
> `{"success": true, "data": <shown-body>, "message": "..."}` — the JSON bodies
> shown in this document are the `data` field's contents, not the literal
> top-level response. Errors are `{"success": false, "error": "...", "message": "...", "code": <http-status>}`,
> not the nested `error.code`/`error.details` shape shown further below.

## 🌐 **Base Endpoints**

### Health Check
```http
GET /health
```

**Response:** a liveness signal only — it does NOT check the database or other
dependencies (unauthenticated, and deliberately omits version/build info to avoid
aiding CVE targeting; get the version from the `system.read`-gated
`/api/v1/system/info` instead).
```json
{
  "status": "healthy",
  "timestamp": "2025-10-08T14:17:46.801479Z",
  "uptime": "5m0.000001541s"
}
```

### OpenAPI Specification
```http
GET /openapi.yaml
```

Returns the complete OpenAPI 3.0 specification for all endpoints.

## 🕒 **Conventions**

### Timestamps
Every timestamp in an API response (`timestamp`, `created_at`, `expires_at`,
`last_activity`, `deleted_at`, …) is **UTC, RFC 3339** (for example
`2026-10-10T01:53:40Z`; sub-second digits appear only when present). The server
never emits a local offset such as `+02:00`, whatever zone it runs in or the
database stored. This is display only: stored values, including everything
covered by the audit hash chain, are not changed. Query parameters that take a
time (`start_time`, `end_time`, `since`) accept any RFC 3339 offset and are
compared as instants.

### Audit log actor kind
`GET /api/v1/audit/logs`, `/audit/search`, `/audit/export` and the CSV export
report each event's `actor` (a username, or `system`) and `actor_type`:

| `actor_type` | Meaning |
|---|---|
| `user` | A signed-in human; `actor` is their username |
| `machine_identity` | A machine identity / token |
| `system` | Keyorix itself (schedulers, rotation, retention, anomaly detection). `actor` is `system` |

An event with no acting user is always reported as `system` (including older
rows that stored an empty or default kind). The filters follow the same rule:
`GET /api/v1/audit/logs?actor_type=system` returns exactly the events shown with
kind `system` (`actor_type=user` only events with a real acting user), and
`GET /api/v1/audit/search?actor=system` (a partial, case-insensitive match, like
a username) finds system events as well as any user whose name contains the term.

## 🔐 **Secret Management API**

### List Secrets
```http
GET /api/v1/secrets
Authorization: Bearer <token>
```

**Query Parameters:**
- `page` (int): Page number, 1-based (default: 1)
- `page_size` (int): Number of secrets per page, max 100 (default: 20)
- `project_id` (int): Project ID filter
- `environment_id` (int): Environment ID filter (a bare `environment` name filter
  is not supported and returns 400 — use the numeric ID, together with `project_id`)

**Response:**
```json
{
  "secrets": [
    {
      "id": 1,
      "name": "example-api-key",
      "type": "api-key-v2",
      "status": "active",
      "project_id": 1,
      "environment_id": 1,
      "created_by": "example-user",
      "created_at": "2025-07-16T21:42:01Z",
      "updated_at": "2025-07-16T21:42:01Z",
      "expires_at": null
    }
  ],
  "total": 14,
  "page": 1,
  "page_size": 20
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
  "project_id": 1,
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
  "project_id": 1,
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
- `include_value` (bool): Include decrypted value in response (default: false)

**Response:**
```json
{
  "id": 1,
  "name": "example-api-key",
  "type": "api-key-v2",
  "status": "active",
  "project_id": 1,
  "environment_id": 1,
  "created_by": "example-user",
  "created_at": "2025-07-16T21:42:01Z",
  "updated_at": "2025-07-16T21:42:01Z",
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

**Response:** `204 No Content` (empty body)

## 🤝 **Secret Sharing API**

### Create Share
```http
POST /api/v1/secrets/{id}/share
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:** (the secret is identified by `{id}` in the path, not a body field)
```json
{
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
  "display_name": "New User",
  "password": "a-strong-password",
  "role": "user"
}
```
`display_name` is required. `password` is optional if `deliver_setup_link` or
`generate_one_time_password` is set instead (the user then sets/receives their
own initial password rather than the admin choosing one).

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
POST /auth/login
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
POST /auth/refresh
Authorization: Bearer <token>
```

### Logout
```http
POST /auth/logout
Authorization: Bearer <token>
```

## 📝 **Error Responses**

All API endpoints return consistent error responses (see the response-envelope
note near the top of this document):

```json
{
  "success": false,
  "error": "ValidationError",
  "message": "Secret name is required",
  "code": 400,
  "details": { "field": "name" }
}
```

`details` is only present when the handler supplies it (often omitted).

### Common `error` values
- `ValidationError` - Invalid request data
- `Unauthorized` - Missing or invalid token
- `Forbidden` - Insufficient permissions
- `NotFound` - Requested resource doesn't exist
- `ConflictError` - Resource with same identifier exists
- `InternalError` - Server-side error

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

## 🔌 **gRPC API** — partial surface, work in progress

> **The HTTP API above is the complete one.** gRPC is a data-plane interface
> covering a subset of it, disabled by default, and still under development.
> Use HTTP unless you specifically need gRPC.

- **Port**: 9090 (default), `server.grpc.enabled: false` by default
- **Services**: 13 services / 86 RPCs — SecretService, ShareService, UserService,
  RoleService, GroupService, ProjectService, AuditService, SystemService,
  BreakGlassService, MachineIdentityService, DynamicSecretService,
  ComplianceService, ConnectService
- **Protocol Buffers**: `server/proto/keyorix.proto`

### What gRPC does not cover

Governance and identity capabilities are HTTP-only today:

| area | HTTP-only capabilities |
|---|---|
| Identity & auth | MFA, step-up, WebAuthn, SSO, SAML, SCIM, personal access tokens, sessions |
| Governance | access-review campaigns, access requests, segregation of duties, legal hold, risk exceptions, permission baseline, anomaly configuration, notification channels, read quota |
| Secret lifecycle | **classification**, **description**, folder CRUD, templates, rotation policies (write), retention override, bulk operations, ownership, access schedule, version comments/diff |

**Enforcement is not affected by this.** Authorization, audit, and the
classification read gate are implemented in core, not in the HTTP handler layer,
so every transport inherits them and gRPC cannot bypass a control HTTP enforces.
Secrets classified `restricted` are unreadable over gRPC when step-up is
required, because gRPC has no step-up — fail-closed by design.

The practical consequence is that some controls cannot be *set* over gRPC, so an
object created there lands in the least-governed state available. **Provision
over HTTP if your deployment has compliance requirements.**

Capability parity with HTTP is a planned project. See
[ADR-105](./adr-105-grpc-scope-and-parity.md) for the scope, the capabilities
deliberately excluded from gRPC, and the phasing.

### Example gRPC Usage
```go
// Use real transport credentials — this connection carries secret material.
creds, err := credentials.NewClientTLSFromFile("certs/ca.crt", "")
if err != nil {
    return err
}
conn, err := grpc.NewClient("localhost:9090", grpc.WithTransportCredentials(creds))
if err != nil {
    return err
}
defer conn.Close()

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