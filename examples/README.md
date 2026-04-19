# Keyorix Examples

This directory contains comprehensive examples demonstrating the key features of the Keyorix secrets management system.

## Available Examples

### 1. 🚀 [System Initialization](system_init/)
**File**: `system_init/main.go`

Demonstrates the complete system setup and validation process:
- System initialization and validation
- File structure verification
- Available commands overview
- Configuration structure
- Security best practices

**Run**: `go run examples/system_init/main.go`

### 2. 🔐 [Encryption](encryption/)
**File**: `encryption/main.go`

Demonstrates the complete encryption functionality:
- Basic secret encryption/decryption
- Large secret chunking
- Key management
- Database integration
- Encryption validation

**Run**: `go run examples/encryption/main.go`

### 3. 🏗️ [New Architecture](new-architecture/)
**File**: `new-architecture/main.go`

Demonstrates the new clean architecture with core package:
- Core service initialization
- Clean separation of concerns
- Modern Go patterns
- Unified storage interface

**Run**: `go run examples/new-architecture/main.go`

### 4. 🔐 [Secret CRUD Operations](secret_crud/)
**File**: `secret_crud/main.go`

Demonstrates comprehensive secret management operations using the new core package:
- Creating secrets with metadata
- Retrieving secret information
- Updating existing secrets
- Listing and filtering secrets
- Working with temporary secrets
- Best practices for secret management

**Run**: `go run examples/secret_crud/main.go`

## Getting Started

### Prerequisites

1. **Initialize Keyorix** (for system_init example):
   ```bash
   keyorix system init
   ```

2. **Go Environment**: Ensure you have Go installed and the project dependencies:
   ```bash
   go mod tidy
   ```

### Running Examples

Each example is self-contained and can be run independently:

```bash
# System initialization example
go run examples/system_init/main.go

# Encryption example (self-contained)
go run examples/encryption/main.go

# New architecture example
go run examples/new-architecture/main.go

# Secret CRUD operations example
go run examples/secret_crud/main.go
```

## Example Structure

```
examples/
├── README.md                    # This file
├── system_init/
│   ├── main.go                 # System initialization demo
│   └── README.md               # Detailed documentation
├── encryption/
│   ├── main.go                 # Encryption functionality demo
│   └── README.md               # Detailed documentation
├── new-architecture/
│   └── main.go                 # New architecture demonstration
└── secret_crud/
    ├── main.go                 # Secret CRUD operations demo
    └── README.md               # Detailed documentation
```

## What You'll Learn

### System Management
- How to initialize a Keyorix system
- Configuration file structure and options
- File permission management
- System validation and auditing
- Security best practices

### Encryption
- AES-256-GCM encryption implementation
- Key management (KEK/DEK)
- Chunked encryption for large secrets
- Database integration with GORM
- Encryption status and validation

### CLI Usage
- System management commands
- Encryption management commands
- Validation and auditing tools
- Interactive setup options

## Real-World Usage Patterns

### Development Workflow
1. **Initialize**: `keyorix system init --interactive`
2. **Validate**: `keyorix system validate`
3. **Use**: Start storing and retrieving secrets
4. **Monitor**: Regular `keyorix system audit`

### Production Deployment
1. **Secure Setup**: Enable all security features
2. **TLS Configuration**: Set up certificates
3. **Key Management**: Secure key storage and rotation
4. **Monitoring**: Regular validation and auditing

### Maintenance Tasks
1. **Key Rotation**: `keyorix encryption rotate`
2. **Permission Audits**: `keyorix system audit`
3. **System Validation**: `keyorix system validate`
4. **Backup Procedures**: Secure key and database backups

## Troubleshooting

### Common Issues

1. **Permission Errors**:
   ```bash
   keyorix system audit
   keyorix system validate --fix
   ```

2. **Missing Files**:
   ```bash
   keyorix system init --force
   ```

3. **Encryption Issues**:
   ```bash
   keyorix encryption validate
   keyorix encryption init
   ```

### Debug Mode

Enable detailed logging:
```bash
export SECRETLY_DEBUG=true
go run examples/system_init/main.go
```

## Additional Resources

- **System Setup Guide**: `../SYSTEM_SETUP.md`
- **Encryption Documentation**: `../internal/encryption/README.md`
- **System Commands**: `../internal/cli/system/README.md`
- **Configuration Reference**: `../keyorix_template.yaml`

## Contributing

When adding new examples:
1. Create a new directory under `examples/`
2. Include a `main.go` file with the example code
3. Add a `README.md` with detailed documentation
4. Update this main README with the new example
5. Ensure examples are self-contained and well-documented

## Support

If you encounter issues with the examples:
1. Check the individual example README files
2. Run `keyorix system validate` for system issues
3. Run `keyorix encryption validate` for encryption issues
4. Review the main documentation files
5. Check file permissions with `keyorix system audit`