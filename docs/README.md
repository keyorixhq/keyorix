# 📚 Keyorix Documentation

Complete documentation for the production-ready Keyorix secret management system.

## 🚀 **Quick Links**

| Document | Description | Status |
|----------|-------------|--------|
| [Main README](../README.md) | Project overview and quick start | ✅ Updated |
| [Quick Start Guide](../QUICK_START.md) | Get running in 5 minutes | ✅ Updated |
| [API Reference](./API_REFERENCE.md) | Complete API documentation | ✅ New |
| [Security Guide](./SECURITY.md) | Security features and best practices | ✅ New |
| [Performance Guide](./PERFORMANCE.md) | Performance metrics and optimization | ✅ New |
| [Self-Hosting Guide](./SELF_HOSTING.md) | Production deployment instructions | ✅ Updated |
| [Migration Guide](./MIGRATION.md) | Import secrets from Vault / AWS / Azure / files | ✅ New |
| [CI/CD Guide](./CI_CD.md) | Fetch secrets in GitHub Actions / GitLab CI / CircleCI | ✅ New |
| [Helm chart](../deploy/helm/keyorix/README.md) | Deploy Keyorix on Kubernetes | ✅ New |

## 📖 **Core Documentation**

### Getting Started
- **[README.md](../README.md)** - Project overview, features, and quick start
- **[QUICK_START.md](../QUICK_START.md)** - 5-minute setup guide
- **[SELF_HOSTING.md](./SELF_HOSTING.md)** - Production deployment

### API Documentation
- **[API_REFERENCE.md](./API_REFERENCE.md)** - REST API reference (complete) and gRPC (partial surface, work in progress)
- **[OpenAPI Spec](../server/http/handlers/openapi.yaml)** - Machine-readable API specification (served at `/openapi.yaml`)
- **Swagger UI** - Interactive API documentation at `/swagger/`

### Security & Compliance
- **[SECURITY.md](./SECURITY.md)** - Security features, encryption, and best practices
- **[security/architecture.md](./security/architecture.md)** - Encryption, key management, authn/authz, transport (covers sharing's crypto model)
- **[SECRET_SHARING_USER_GUIDE.md](./SECRET_SHARING_USER_GUIDE.md)** - User guide for sharing

### Performance & Operations
- **[PERFORMANCE.md](./PERFORMANCE.md)** - Performance metrics and optimization
- **[edge-deployment.md](./edge-deployment.md)** - Edge and industrial devices: SQLite, audit durability, power loss, air-gapped updates, hardening
- **[TESTING_FRAMEWORK.md](./TESTING_FRAMEWORK.md)** - Testing strategy and results

### Development & Architecture
- **[TESTING_BEST_PRACTICES.md](./TESTING_BEST_PRACTICES.md)** - Testing guidelines
- **[Server README](../server/README.md)** - Server architecture and setup
- **[Web Dashboard README](../web/README.md)** - Frontend documentation

## 🎯 **Documentation by Use Case**

### For Developers
1. **Getting Started**: [README.md](../README.md) → [QUICK_START.md](../QUICK_START.md)
2. **API Integration**: [API_REFERENCE.md](./API_REFERENCE.md)
3. **Testing**: [TESTING_FRAMEWORK.md](./TESTING_FRAMEWORK.md)
4. **Security**: [SECURITY.md](./SECURITY.md)

### For DevOps/SRE
1. **Deployment**: [SELF_HOSTING.md](./SELF_HOSTING.md)
2. **Performance**: [PERFORMANCE.md](./PERFORMANCE.md)
3. **Security**: [SECURITY.md](./SECURITY.md)
4. **Monitoring**: Health checks at `/health`
5. **Edge / air-gapped devices**: [edge-deployment.md](./edge-deployment.md)

### For End Users
1. **Quick Start**: [QUICK_START.md](../QUICK_START.md)
2. **Secret Sharing**: [SECRET_SHARING_USER_GUIDE.md](./SECRET_SHARING_USER_GUIDE.md)
3. **API Usage**: [API_REFERENCE.md](./API_REFERENCE.md)
4. **Web Interface**: [Web README](../web/README.md)

### For Security Teams
1. **Security Overview**: [SECURITY.md](./SECURITY.md)
2. **Sharing Security**: [security/architecture.md](./security/architecture.md)
3. **API Security**: [API_REFERENCE.md](./API_REFERENCE.md#-authentication)
4. **Hardening**: [security/hardening-guide.md](./security/hardening-guide.md)

## 📊 **System Status**

What this project states about itself, and where each statement is checked:

- **Encryption**: secrets are encrypted at rest with AES-256-GCM; details and limits in [SECURITY.md](./SECURITY.md).
- **API**: the HTTP API is the complete surface and is described by the generated OpenAPI document; gRPC covers the data plane only (see ADR-105).
- **Readiness**: whether a given build is fit for your deployment is decided by your own acceptance run, not by this page. `scripts/demo/check.sh` is the readiness check the demo uses; `keyorix-server admin validate --posture` reports the security posture of a configuration.
- **Test results**: the CI run for the commit you deploy is the record. This page carries no pass rates, response times, memory or uptime figures, because they would go stale the day after they were written.

## 🔧 **Quick Reference**

### Essential Commands
```bash
# Start the system
./keyorix-server &

# Create a secret
./keyorix secret create --name "api-key" --interactive   # value typed at a hidden prompt

# List secrets
./keyorix secret list

# Check system health
curl http://localhost:8080/health

# View API documentation
curl http://localhost:8080/openapi.yaml
```

### Essential URLs
- **Health Check**: `http://localhost:8080/health`
- **API Base**: `http://localhost:8080/api/v1/`
- **OpenAPI Spec**: `http://localhost:8080/openapi.yaml`
- **Swagger UI**: `http://localhost:8080/swagger/` (if enabled)

### Configuration Files
- **Main Config**: `keyorix.yaml`
- **Production Config**: `server/config/production.yaml`
- **Docker Compose**: `docker-compose.full-stack.yml`

## 🆘 **Support & Resources**

### Getting Help
- **Documentation**: This directory contains all guides
- **API Reference**: Complete endpoint documentation available
- **Health Monitoring**: Real-time system status at `/health`
- **Test Results**: Comprehensive validation in test reports

### Troubleshooting
1. **Check Health**: `curl http://localhost:8080/health`
2. **View Logs**: Server logs for error details
3. **Test CLI**: `./keyorix status` for system status
4. **Verify Config**: Check `keyorix.yaml` configuration

### Additional Resources
- **Examples**: See `/examples` directory
- **Scripts**: Automation scripts in `/scripts`
- **Tests**: Comprehensive test suite validation

## 🎉 **Documentation Status**

These guides are maintained alongside the code, but no page here certifies itself. When a guide and the behaviour of the version you run disagree, the running server (`/openapi.yaml`, `keyorix --help`) is right; please open an issue.
