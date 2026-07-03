-- 🌐 Reference tables: namespaces, zones, environments

CREATE TABLE IF NOT EXISTS namespaces (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  description TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS zones (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  description TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS environments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE
);

-- 🔐 Secrets and versions

CREATE TABLE IF NOT EXISTS secret_nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  parent_id INTEGER REFERENCES secret_nodes(id) ON DELETE CASCADE,
  namespace_id INTEGER NOT NULL REFERENCES namespaces(id),
  zone_id INTEGER NOT NULL REFERENCES zones(id),
  environment_id INTEGER NOT NULL REFERENCES environments(id),
  name TEXT NOT NULL,
  is_secret BOOLEAN NOT NULL DEFAULT 0,
  type TEXT,
  max_reads INTEGER,
  expiration TIMESTAMP,
  metadata TEXT,
  status TEXT DEFAULT 'active',
  created_by TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS secret_versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  secret_node_id INTEGER NOT NULL REFERENCES secret_nodes(id) ON DELETE CASCADE,
  version_number INTEGER NOT NULL,
  encrypted_value BLOB NOT NULL,
  encryption_metadata TEXT,
  read_count INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS secret_access_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  secret_node_id INTEGER NOT NULL REFERENCES secret_nodes(id),
  secret_version_id INTEGER NOT NULL REFERENCES secret_versions(id),
  accessed_by TEXT,
  access_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  action TEXT,
  ip_address TEXT,
  user_agent TEXT
);

CREATE TABLE IF NOT EXISTS secret_metadata_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  secret_node_id INTEGER NOT NULL REFERENCES secret_nodes(id),
  changed_by TEXT,
  change_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  old_metadata TEXT,
  new_metadata TEXT
);

-- 🧑‍💻 Users, roles, groups

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  email TEXT,
  password_hash TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  description TEXT
);

CREATE TABLE IF NOT EXISTS user_roles (
  user_id INTEGER NOT NULL REFERENCES users(id),
  role_id INTEGER NOT NULL REFERENCES roles(id),
  namespace_id INTEGER REFERENCES namespaces(id),
  PRIMARY KEY (user_id, role_id, namespace_id)
);

CREATE TABLE IF NOT EXISTS groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  description TEXT
);

CREATE TABLE IF NOT EXISTS user_groups (
  user_id INTEGER NOT NULL REFERENCES users(id),
  group_id INTEGER NOT NULL REFERENCES groups(id),
  PRIMARY KEY (user_id, group_id)
);

CREATE TABLE IF NOT EXISTS group_roles (
  group_id INTEGER NOT NULL REFERENCES groups(id),
  role_id INTEGER NOT NULL REFERENCES roles(id),
  namespace_id INTEGER REFERENCES namespaces(id),
  PRIMARY KEY (group_id, role_id, namespace_id)
);

-- 🛡️ Authentication

CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  session_token TEXT NOT NULL UNIQUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS password_resets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  token TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 🏷️ Tags

CREATE TABLE IF NOT EXISTS tags (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS secret_tags (
  secret_node_id INTEGER NOT NULL REFERENCES secret_nodes(id),
  tag_id INTEGER NOT NULL REFERENCES tags(id),
  PRIMARY KEY (secret_node_id, tag_id)
);

-- 📬 Notifications

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  secret_node_id INTEGER REFERENCES secret_nodes(id),
  type TEXT NOT NULL,
  message TEXT NOT NULL,
  is_read BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  user_id INTEGER REFERENCES users(id),
  secret_node_id INTEGER REFERENCES secret_nodes(id),
  description TEXT,
  event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ⚙️ Settings

CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id),
  key TEXT NOT NULL,
  value TEXT,
  UNIQUE(user_id, key)
);

CREATE TABLE IF NOT EXISTS system_metadata (
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 🔐 API and integrations

CREATE TABLE IF NOT EXISTS api_clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  client_id TEXT NOT NULL UNIQUE,
  client_secret TEXT NOT NULL,
  scopes TEXT,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER NOT NULL REFERENCES api_clients(id),
  user_id INTEGER REFERENCES users(id),
  token TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  scope TEXT,
  revoked BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS rate_limits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER NOT NULL REFERENCES api_clients(id),
  method TEXT NOT NULL,
  limit_per_minute INTEGER NOT NULL DEFAULT 60,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_call_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER REFERENCES api_clients(id),
  user_id INTEGER REFERENCES users(id),
  method TEXT,
  path TEXT,
  status_code INTEGER,
  duration_ms INTEGER,
  ip_address TEXT,
  user_agent TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 🧠 gRPC

CREATE TABLE IF NOT EXISTS grpc_services (
  name TEXT PRIMARY KEY,
  version TEXT,
  description TEXT
);

-- 🌐 IdentityProvider (OIDC/LDAP/SSO)

CREATE TABLE IF NOT EXISTS identity_providers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL,
  config TEXT NOT NULL,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS external_identities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  provider_id INTEGER NOT NULL REFERENCES identity_providers(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  external_id TEXT NOT NULL,
  email TEXT,
  name TEXT,
  metadata TEXT,
  linked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
