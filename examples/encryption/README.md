# Encryption Example

This example demonstrates the complete encryption functionality of Keyorix, including key management, secret encryption/decryption, and chunked encryption for large data.

## What This Example Shows

1. **Basic Encryption** - Encrypt and decrypt simple secrets
2. **Large Secret Handling** - Chunked encryption for large data (150KB example)
3. **Encryption Status** - How to check encryption service status
4. **Validation** - How to validate encryption setup
5. **Key Management** - Automatic key generation and management

## Running the Example

```bash
# From the project root directory
go run examples/encryption/main.go
```

## Prerequisites

This example is self-contained and will:
- Create temporary encryption keys
- Set up a temporary database
- Demonstrate all encryption features
- Clean up temporary files when done

No prior setup is required!

## Expected Output

The example will demonstrate:
- ✅ Encryption service initialization
- 🔐 Simple secret encryption and decryption
- 📦 Large secret chunking (3 chunks for 150KB data)
- 📊 Encryption status reporting
- ✅ Encryption setup validation
- 🧹 Automatic cleanup of temporary files

## Features Demonstrated

### 1. Simple Secret Encryption
```go
plaintext := []byte("super_secret_password_123!")
version, err := secretEncryption.StoreSecret(secretNode, plaintext)
retrieved, err := secretEncryption.RetrieveSecret(version.ID)
```

### 2. Large Secret Chunking
```go
largeSecret := make([]byte, 150*1024) // 150KB
versions, err := secretEncryption.StoreLargeSecret(secretNode, largeSecret, 64) // 64KB chunks
retrievedLarge, err := secretEncryption.RetrieveLargeSecret(secretNode.ID)
```

### 3. Encryption Status
```go
status := secretEncryption.GetEncryptionStatus()
// Returns: map[enabled:true initialized:true key_version:v1]
```

### 4. Validation
```go
err := secretEncryption.ValidateEncryption()
// Validates encryption setup and key files
```

## Technical Details

### Encryption Specifications
- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Size**: 256-bit (32 bytes)
- **Key Management**: Separate KEK (Key Encryption Key) and DEK (Data Encryption Key)
- **Chunking**: Configurable chunk size (default 64KB)
- **Metadata**: JSON metadata with encryption details

### Security Features
- Cryptographically secure random key generation
- Proper nonce generation for each encryption operation
- Authenticated encryption prevents tampering
- Secure key storage with proper file permissions
- Key versioning for rotation support

## Integration with Database

The example shows how encryption integrates with GORM models:
- `SecretNode` - Represents a secret in the hierarchy
- `SecretVersion` - Stores encrypted data and metadata
- Automatic chunking for large secrets
- Metadata storage in JSON format

## What You'll Learn

- How to initialize the encryption service
- How to encrypt and decrypt secrets of any size
- How chunked encryption works for large data
- How to check encryption status and validate setup
- How encryption integrates with the database layer
- Security best practices for key management

## Next Steps

After running this example:
1. Try modifying the chunk size and see how it affects the number of chunks
2. Experiment with different secret sizes
3. Look at the generated metadata to understand the encryption details
4. Try the encryption CLI commands: `keyorix encryption status`, `keyorix encryption validate`