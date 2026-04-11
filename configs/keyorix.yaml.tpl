# secretly_template.yaml
# Default configuration template for Secretly.
#
# IMPORTANT: Never store API keys or credentials directly in this file.
# Use environment variables instead:
#   KEYORIX_API_KEY        - API key for client authentication
#   KEYORIX_REMOTE_API_KEY - API key for remote storage backend

locale:
  # Primary language for the application interface
  # Supported languages: en (English), ru (Russian), es (Spanish), fr (French), de (German)
  language: "en"
  
  # Fallback language when translations are missing in the primary language
  # Should be one of the supported languages, typically "en" for maximum compatibility
  fallback_language: "en"

server:
  http:
    # Enable HTTP server
    enabled: true
    port: "8080"
    protocol_versions: ["1.1"]
    tls:
      # Enable TLS on HTTP
      enabled: false
      cert_file: "certs/server.crt"     # Path to TLS certificate
      key_file: "certs/server.key"      # Path to TLS key
      allowed_ciphers: []               # Optional cipher list
    ratelimit:
      # Enable rate limiting
      enabled: false
      requests_per_second: 10
      burst: 20

  grpc:
    # Enable gRPC server
    enabled: false
    port: "9090"
    protocol_versions: ["1.0"]
    tls:
      enabled: false
      cert_file: "certs/server.crt"
      key_file: "certs/server.key"
      allowed_ciphers: []
    ratelimit:
      enabled: false
      requests_per_second: 10
      burst: 20

storage:
  type: sqlite  # options: sqlite, postgres

  database:
    # SQLite (default — zero infrastructure required)
    path: "secretly.db"

    # PostgreSQL (recommended for production)
    # type: postgres
    # Option A — full DSN:
    # dsn: "host=localhost user=keyorix dbname=keyorix port=5432 sslmode=require"
    # Option B — field by field:
    # host: localhost
    # port: "5432"
    # name: keyorix
    # user: keyorix
    # password: ""  # use KEYORIX_DB_PASSWORD environment variable instead
    # ssl_mode: require  # always use require or verify-full in production

    max_open_conns: 25
    max_idle_conns: 5
    conn_max_lifetime_minutes: 30

  encryption:
    # Enable envelope encryption
    enabled: true
    # Use Key Encryption Key (KEK) and Data Encryption Key (DEK)
    use_kek: true
    kek_path: "keys/kek.key"
    dek_path: "keys/dek.key"

secrets:
  chunking:
    # Enable chunking large secrets into smaller parts
    enabled: true
    max_chunk_size_kb: 64
    max_chunks_per_secret: 10

  limits:
    # Maximum number of secrets per user
    max_secrets_per_user: 1000

security:
  # Check file permission safety on startup
  enable_file_permission_check: true
  auto_fix_file_permissions: true
  allow_unsafe_file_permissions: false

soft_delete:
  # Enable soft-deletion for all database entities
  enabled: true
  retention_days: 30

purge:
  # Enable periodic purge of expired/deleted database entities 
  enabled: true
  schedule: "0 0 * * *"

logging:
  # Enable logging
  enabled: true
  # Log level: debug, info, warn, error
  level: "info"
  # Path to log file
  file: "secretly.log"
  # Log format
  log_format: "text"  