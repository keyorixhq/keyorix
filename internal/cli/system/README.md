# System Management Commands

This package provides comprehensive system management commands for the Secretly secrets management system. These commands handle initialization, validation, and maintenance of the system configuration and supporting files.

## Commands Overview

### `secretly system init`
Initialize the Secretly system with configuration files and required components.

**Usage:**
```bash
# Initialize all components with default settings
secretly system init

# Interactive setup wizard
secretly system init --interactive

# Initialize specific components only
secretly system init --encryption
secretly system init --database
secretly system init --logging

# Use custom config file path
secretly system init --config ./my-config.yaml

# Overwrite existing files (dangerous)
secretly system init --force
```

**What it does:**
1. **Config Generation**: Creates `secretly.yaml` from template
2. **Encryption Setup**: Generates KEK/DEK keys with secure permissions
3. **Database Setup**: Creates SQLite database file
4. **Logging Setup**: Creates log files and directories
5. **TLS Setup**: Validates TLS configuration (certificates not auto-generated)
7. **Permission Validation**: Ensures all files have correct permissions

### `secretly system validate`
Perform comprehensive validation of the system setup.

**Usage:**
```bash
# Validate current setup
secretly system validate

# Validate specific config file
secretly system validate --config ./my-config.yaml

# Attempt to fix issues automatically
secretly system validate --fix
```

**What it validates:**
- Configuration file syntax and completeness
- File permissions and ownership
- Encryption key existence and validity
- Database accessibility
- TLS certificate availability (if enabled)

### `secretly system audit`
Audit critical file permissions and ownership.

**Usage:**
```bash
# Audit file permissions
secretly system audit
```

**What it checks:**
- Config file permissions (should be 0600)
- Encryption key permissions (should be 0600)
- Database file permissions (should be 0600)
- TLS certificate permissions (should be 0600)
- File ownership (should be current user)

## File Structure

After running `secretly system init`, your directory should contain:

```
.
├── secretly.yaml          # Main configuration file (0600)
├── secretly_template.yaml # Template file (0644)
├── keys/
│   ├── kek.key            # Key Encryption Key (0600)
│   └── dek.key            # Data Encryption Key (0600)
├── secretly.db            # SQLite database (0600)
├── secretly.log           # Application logs (0644)
└── certs/                 # TLS certificates (if enabled)
    ├── server.crt         # TLS certificate (0600)
    └── server.key         # TLS private key (0600)
```

## Configuration Template

The system uses `secretly_template.yaml` as the base template for generating configuration files. The template includes:

- **Locale Settings**: Language and localization
- **Server Configuration**: HTTP and gRPC server settings
- **Storage Configuration**: Database and encryption settings
- **Security Policies**: File permission and security controls
- **Operational Settings**: Logging, soft delete, purge

## Security Features

### File Permission Management
- All critical files are created with secure permissions (0600)
- Automatic permission validation on startup
- Optional automatic permission fixing
- Ownership validation (files must be owned by current user)

### Encryption Key Management
- Separate KEK (Key Encryption Key) and DEK (Data Encryption Key)
- Keys are generated with cryptographically secure random data
- Key files are validated for correct size (32 bytes for AES-256)
- Integration with the encryption service for key rotation

### Configuration Security
- Config files are created with 0600 permissions
- Path validation prevents directory traversal
- Secure file operations with base directory validation

## Interactive Mode

The interactive mode (`--interactive`) provides a guided setup experience:

1. **Server Configuration**: HTTP/gRPC ports and settings
2. **Encryption Settings**: Enable/disable encryption and key paths
3. **Database Configuration**: Database file location
4. **Security Policies**: Permission checking and auto-fix settings

## Error Handling

The system provides comprehensive error handling and user guidance:

- **Missing Files**: Clear messages about what files are missing
- **Permission Issues**: Detailed information about incorrect permissions
- **Configuration Errors**: Specific validation error messages
- **Recovery Suggestions**: Actionable recommendations for fixing issues

## Integration with Other Components

### Encryption Service
- Automatic initialization of encryption keys
- Integration with key rotation functionality
- Validation of encryption setup

### Database Management
- Database file creation and permission setting
- Integration with GORM migrations
- Validation of database accessibility

### Startup Validation
- Comprehensive validation on system startup
- Configurable validation policies
- Integration with security settings

## Best Practices

1. **Always validate** after initialization: `secretly system validate`
2. **Use secure permissions** in production environments
3. **Backup encryption keys** before rotation
4. **Monitor file permissions** regularly with audit command
5. **Use interactive mode** for first-time setup
6. **Test configuration** before deploying to production

## Troubleshooting

### Common Issues

1. **Permission Denied Errors**
   - Run `secretly system audit` to check permissions
   - Use `--fix` flag to automatically correct permissions
   - Ensure you own all the files

2. **Missing Configuration**
   - Run `secretly system init` to create missing files
   - Use `--force` to overwrite corrupted files
   - Check template file exists

3. **Encryption Key Issues**
   - Run `secretly encryption init` to regenerate keys
   - Validate key file sizes (should be 32 bytes)
   - Check key file permissions (should be 0600)

4. **Database Issues**
   - Ensure database directory exists and is writable
   - Check database file permissions
   - Verify SQLite is available

### Debug Mode

Set environment variable for detailed logging:
```bash
export SECRETLY_DEBUG=true
secretly system init
```

## Examples

See `examples/system_init_example.go` for comprehensive usage examples including:
- System validation
- File structure verification
- Command demonstrations
- Security recommendations