# Doorman API Gateway - Documentation

Welcome to the Doorman API Gateway documentation. This guide will help you set up, configure, secure, and operate your API gateway.

## Documentation Index

### 1. [Getting Started](./01-getting-started.md)
**Start here** - Installation, quick start, and your first API setup
- Local development setup
- Docker Compose deployment
- First admin login
- Creating your first API

### 2. [Configuration Reference](./02-configuration.md)
Complete guide to environment variables and configuration options
- Environment variables explained
- Cache and database modes (Memory, Redis, MongoDB)
- HTTPS and TLS configuration
- CORS and security settings

### 3. [Security Guide](./03-security.md)
Comprehensive security features and best practices
- HTTPS enforcement and TLS
- Authentication and JWT tokens
- CSRF protection
- IP access control and whitelisting
- Request validation and limits
- Audit logging and monitoring

### 4. [API Workflows](./04-api-workflows.md)
Real-world examples and end-to-end workflows
- Publishing REST APIs with API key injection
- Client-specific routing
- Per-user token management
- GraphQL gateway setup
- SOAP API configuration
- Common errors and troubleshooting

### 5. [Operations Guide](./05-operations.md)
Production deployment, monitoring, and runbooks
- Production deployment checklist
- Health checks and monitoring endpoints
- Redis and MongoDB setup
- Graceful restarts and memory dumps
- Runbooks for common issues
- Response envelope configuration

### 6. [Tools and Diagnostics](./06-tools.md)
Built-in tools for troubleshooting and validation
- CORS checker tool
- Diagnostic endpoints
- Log analysis

### 8. [AI Gateway](./08-ai-gateway.md)
Connect organization-owned AI providers, govern model access, measure tokens and
cost, and configure budgets, guardrails and prompt privacy.

---

## Quick Links

- **Main README**: [../README.md](../README.md)
- **GitHub Repository**: [https://github.com/apidoorman/doorman](https://github.com/apidoorman/doorman)
- **License**: [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0)

## Need Help?

- Check the [API Workflows](./04-api-workflows.md) for common use cases
- Review the [Operations Guide](./05-operations.md) for production issues
- Use the [CORS Checker](./06-tools.md) to diagnose CORS problems
- Consult the [Security Guide](./03-security.md) for hardening best practices
