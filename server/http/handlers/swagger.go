package handlers

import (
	"net/http"
	"strings"
)

// SwaggerHandler returns a handler for serving Swagger UI
func SwaggerHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/swagger/")

		switch path {
		case "", "index.html":
			serveSwaggerIndex(w, r)
		case "swagger.json":
			serveSwaggerSpec(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// serveSwaggerIndex serves the Swagger UI HTML
func serveSwaggerIndex(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Keyorix API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css" />
    <style>
        html {
            box-sizing: border-box;
            overflow: -moz-scrollbars-vertical;
            overflow-y: scroll;
        }
        *, *:before, *:after {
            box-sizing: inherit;
        }
        body {
            margin:0;
            background: #fafafa;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: '/swagger/swagger.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            });
        };
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}

// serveSwaggerSpec serves the OpenAPI specification in JSON format
func serveSwaggerSpec(w http.ResponseWriter, r *http.Request) {
	spec := `{
  "openapi": "3.0.3",
  "info": {
    "title": "Keyorix API",
    "description": "Secure secrets management API",
    "version": "1.0.0",
    "contact": {
      "name": "Keyorix Team",
      "email": "support@keyorix.dev"
    }
  },
  "servers": [
    {
      "url": "/api/v1",
      "description": "API v1"
    }
  ],
  "security": [
    {
      "bearerAuth": []
    }
  ],
  "components": {
    "securitySchemes": {
      "bearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT"
      }
    },
    "schemas": {
      "Secret": {
        "type": "object",
        "properties": {
          "id": {"type": "integer"},
          "name": {"type": "string"},
          "namespace": {"type": "string"},
          "zone": {"type": "string"},
          "environment": {"type": "string"},
          "type": {"type": "string"},
          "max_reads": {"type": "integer", "nullable": true},
          "expiration": {"type": "string", "format": "date-time", "nullable": true},
          "metadata": {"type": "object"},
          "tags": {"type": "array", "items": {"type": "string"}},
          "created_by": {"type": "string"},
          "created_at": {"type": "string", "format": "date-time"},
          "updated_at": {"type": "string", "format": "date-time"}
        }
      },
      "SecretRequest": {
        "type": "object",
        "required": ["name", "value", "namespace", "zone", "environment"],
        "properties": {
          "name": {"type": "string"},
          "value": {"type": "string"},
          "namespace": {"type": "string"},
          "zone": {"type": "string"},
          "environment": {"type": "string"},
          "type": {"type": "string"},
          "max_reads": {"type": "integer"},
          "expiration": {"type": "string", "format": "date-time"},
          "metadata": {"type": "object"},
          "tags": {"type": "array", "items": {"type": "string"}}
        }
      },
      "User": {
        "type": "object",
        "properties": {
          "id": {"type": "integer"},
          "username": {"type": "string"},
          "email": {"type": "string"},
          "created_at": {"type": "string", "format": "date-time"}
        }
      },
      "Role": {
        "type": "object",
        "properties": {
          "id": {"type": "integer"},
          "name": {"type": "string"},
          "description": {"type": "string"}
        }
      },
      "Error": {
        "type": "object",
        "properties": {
          "error": {"type": "string"},
          "message": {"type": "string"},
          "code": {"type": "integer"}
        }
      }
    }
  },
  "paths": {
    "/health": {
      "get": {
        "summary": "Health check",
        "security": [],
        "responses": {
          "200": {
            "description": "Service is healthy",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "status": {"type": "string"},
                    "timestamp": {"type": "string", "format": "date-time"},
                    "version": {"type": "string"},
                    "services": {"type": "object"}
                  }
                }
              }
            }
          }
        }
      }
    },
    "/secrets": {
      "get": {
        "summary": "List secrets",
        "parameters": [
          {"name": "namespace", "in": "query", "schema": {"type": "string"}},
          {"name": "zone", "in": "query", "schema": {"type": "string"}},
          {"name": "environment", "in": "query", "schema": {"type": "string"}},
          {"name": "page", "in": "query", "schema": {"type": "integer", "default": 1}},
          {"name": "page_size", "in": "query", "schema": {"type": "integer", "default": 20}}
        ],
        "responses": {
          "200": {
            "description": "List of secrets",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "secrets": {"type": "array", "items": {"$ref": "#/components/schemas/Secret"}},
                    "total": {"type": "integer"},
                    "page": {"type": "integer"},
                    "page_size": {"type": "integer"},
                    "total_pages": {"type": "integer"}
                  }
                }
              }
            }
          }
        }
      },
      "post": {
        "summary": "Create secret",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {"$ref": "#/components/schemas/SecretRequest"}
            }
          }
        },
        "responses": {
          "201": {
            "description": "Secret created",
            "content": {
              "application/json": {
                "schema": {"$ref": "#/components/schemas/Secret"}
              }
            }
          }
        }
      }
    },
    "/secrets/{id}": {
      "get": {
        "summary": "Get secret",
        "parameters": [
          {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}},
          {"name": "include_value", "in": "query", "schema": {"type": "boolean", "default": false}}
        ],
        "responses": {
          "200": {
            "description": "Secret details",
            "content": {
              "application/json": {
                "schema": {"$ref": "#/components/schemas/Secret"}
              }
            }
          }
        }
      },
      "put": {
        "summary": "Update secret",
        "parameters": [
          {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {"$ref": "#/components/schemas/SecretRequest"}
            }
          }
        },
        "responses": {
          "200": {
            "description": "Secret updated",
            "content": {
              "application/json": {
                "schema": {"$ref": "#/components/schemas/Secret"}
              }
            }
          }
        }
      },
      "delete": {
        "summary": "Delete secret",
        "parameters": [
          {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}
        ],
        "responses": {
          "204": {"description": "Secret deleted"}
        }
      }
    }
  }
}`

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(spec))
}

// OpenAPISpec serves the OpenAPI specification in YAML format
func OpenAPISpec(w http.ResponseWriter, r *http.Request) {
	// This would typically be loaded from a file
	spec := `openapi: 3.0.3
info:
  title: Keyorix API
  description: Secure secrets management API
  version: 1.0.0
  contact:
    name: Keyorix Team
    email: support@keyorix.dev
servers:
  - url: /api/v1
    description: API v1
security:
  - bearerAuth: []
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
  schemas:
    Secret:
      type: object
      properties:
        id:
          type: integer
        name:
          type: string
        namespace:
          type: string
        zone:
          type: string
        environment:
          type: string
        type:
          type: string
        max_reads:
          type: integer
          nullable: true
        expiration:
          type: string
          format: date-time
          nullable: true
        metadata:
          type: object
        tags:
          type: array
          items:
            type: string
        created_by:
          type: string
        created_at:
          type: string
          format: date-time
        updated_at:
          type: string
          format: date-time
paths:
  /health:
    get:
      summary: Health check
      security: []
      responses:
        '200':
          description: Service is healthy
  /secrets:
    get:
      summary: List secrets
      parameters:
        - name: namespace
          in: query
          schema:
            type: string
        - name: zone
          in: query
          schema:
            type: string
        - name: environment
          in: query
          schema:
            type: string
        - name: page
          in: query
          schema:
            type: integer
            default: 1
        - name: page_size
          in: query
          schema:
            type: integer
            default: 20
      responses:
        '200':
          description: List of secrets
    post:
      summary: Create secret
      responses:
        '201':
          description: Secret created`

	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(spec))
}
