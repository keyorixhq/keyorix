# keyorix_template.yaml
# Default configuration template for Keyorix.
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
    path: "keyorix.db"

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
    salt_path: "keys/kek.salt"

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

password_policy:
  # Rules enforced when a user sets a new password (e.g. self-service change).
  # Omit this whole block to use the conservative built-in defaults (shown
  # below). Lab installs may relax these, e.g. min_length: 8 and the require_*
  # flags false.
  min_length: 16
  require_uppercase: true
  require_lowercase: true
  require_digit: true
  require_special: true
  reject_personal_info: true     # reject if it contains the user's username/email/display name
  reject_common_passwords: true  # reject passwords on the curated common-password denylist
  history_count: 5               # forbid reusing the last N passwords (0 = off)
  max_age_days: 0                # expire a password after N days (0 = never; login flags it)

soft_delete:
  # Enable soft-deletion for all database entities
  enabled: true
  retention_days: 30

purge:
  # Enable periodic purge of expired/deleted database entities
  enabled: true
  schedule: "0 0 * * *"

audit:
  # Native SIEM push: forward every audit event to an external SIEM.
  # Audit events carry no plaintext secret values, so they are safe to ship.
  siem:
    enabled: false
    # provider: splunk | datadog | webhook
    provider: "splunk"
    # Full destination URL (e.g. a Splunk HEC collector endpoint).
    endpoint: ""
    # HEC token / DD-API-KEY / bearer token. Prefer the KEYORIX_SIEM_TOKEN env var.
    token: ""
    # Skip TLS verification for self-signed SIEM endpoints (not recommended).
    insecure_skip_verify: false

logging:
  # Enable logging
  enabled: true
  # Log level: debug, info, warn, error
  level: "info"
  # Path to log file
  file: "keyorix.log"
  # Log format
  log_format: "text"  