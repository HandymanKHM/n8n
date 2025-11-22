## Reporting a Vulnerability

If you discover a (suspected) security vulnerability, please report it through our [Vulnerability Disclosure Program](https://n8n.notion.site/n8n-vulnerability-disclosure-program).

**Do NOT open a public GitHub issue for security vulnerabilities.**

## Security Resources

For developers and operators working with n8n, we provide comprehensive security documentation:

- **[Security Best Practices](SECURITY_BEST_PRACTICES.md)** - Deployment and configuration guide
- **[Security Analysis](SECURITY_ANALYSIS.md)** - Current security controls and roadmap
- **[HTML Sanitization Security](HTML_SANITIZATION_SECURITY.md)** - XSS prevention guidance
- **[@n8n/config Security Module](packages/@n8n/config/SECURITY_README.md)** - Security validators and defaults

## Security Features

### Input Validation

n8n includes security validators to protect against common attacks:

- **SSRF Protection** - Blocks requests to localhost and private IP ranges
- **Path Traversal Prevention** - Validates file paths against allowed directories
- **Password Strength** - Enforces strong passwords and detects weak patterns
- **Email Validation** - RFC-compliant email validation with domain controls

See the [@n8n/config package](packages/@n8n/config/SECURITY_README.md) for implementation details.

### Secure Defaults

Security-critical configurations use secure defaults:

- **Content Security Policy (CSP)** - Protects against XSS attacks (with documented limitations)
- **Cookie Security** - HttpOnly, Secure, and SameSite flags configured appropriately
- **File Access** - Restricted to specific directories by default

### Security Scanning

The repository includes automated security scanning:

- **Dependency Audits** - Regular vulnerability scanning of dependencies
- **Secret Scanning** - Detects accidentally committed secrets
- **License Compliance** - Ensures license compatibility
- **Static Analysis** - Semgrep rules for security issues

See `.github/workflows/security-scan.yml` for configuration details.

## Security Configuration

### Environment Variables

Key security-related environment variables:

```bash
# File access restrictions
N8N_BLOCK_FILE_ACCESS_TO_N8N_FILES=true
N8N_RESTRICT_FILE_ACCESS_TO="/app/data;/app/uploads"

# Content Security Policy
N8N_CONTENT_SECURITY_POLICY='{"frame-ancestors": ["'none'"]}'
N8N_CONTENT_SECURITY_POLICY_REPORT_ONLY=false

# Encryption
N8N_ENCRYPTION_KEY="<strong-random-key>"
N8N_JWT_SECRET="<strong-random-secret>"

# HTTPS (production)
N8N_PROTOCOL=https
N8N_SSL_KEY="/path/to/private-key.pem"
N8N_SSL_CERT="/path/to/certificate.pem"
```

See [Security Best Practices](SECURITY_BEST_PRACTICES.md) for a complete configuration guide.

## Running Security Scans

### Locally

```bash
# Dependency vulnerabilities
pnpm audit

# Security validator tests
pnpm test --filter @n8n/config

# Full test suite
pnpm test
```

### CI/CD

The security scan workflow runs automatically on:
- Pull requests
- Pushes to main/master
- Weekly schedule (Mondays at 9 AM UTC)
- Manual trigger

## Security Advisories

Security advisories for n8n are published through:
- [GitHub Security Advisories](https://github.com/n8n-io/n8n/security/advisories)
- [n8n Security Blog](https://n8n.io/blog/tag/security/)

Subscribe to GitHub repository notifications to receive security updates.
