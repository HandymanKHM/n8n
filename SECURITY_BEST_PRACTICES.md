# Security Best Practices for n8n Deployment

This document provides guidance on deploying and configuring n8n securely, leveraging the built-in security validators and secure defaults.

## Table of Contents

1. [Input Validation](#input-validation)
2. [URL and SSRF Protection](#url-and-ssrf-protection)
3. [Path Traversal Protection](#path-traversal-protection)
4. [Password and Secret Management](#password-and-secret-management)
5. [Email Validation](#email-validation)
6. [Content Security Policy (CSP)](#content-security-policy-csp)
7. [Cookie Security](#cookie-security)
8. [HTTPS and TLS](#https-and-tls)
9. [Environment Configuration](#environment-configuration)
10. [Monitoring and Auditing](#monitoring-and-auditing)

## Input Validation

### Using the Security Validators

The `@n8n/config` package provides security validators for common attack vectors. Import and use them in your code:

```typescript
import {
  validateUrl,
  validatePath,
  validatePassword,
  validateEmail,
} from '@n8n/config';

// SSRF protection
const urlResult = validateUrl(userProvidedUrl);
if (!urlResult.isValid) {
  throw new Error(`Invalid URL: ${urlResult.error}`);
}

// Path traversal protection
const pathResult = validatePath(userPath, { basePath: '/allowed/directory' });
if (!pathResult.isValid) {
  throw new Error(`Invalid path: ${pathResult.error}`);
}

// Password strength
const passwordResult = validatePassword(userPassword, {
  minLength: 12,
  requireUppercase: true,
  requireDigit: true,
  requireSpecialChar: true,
});
if (!passwordResult.isValid) {
  throw new Error(`Weak password: ${passwordResult.error}`);
}

// Email validation
const emailResult = validateEmail(userEmail);
if (!emailResult.isValid) {
  throw new Error(`Invalid email: ${emailResult.error}`);
}
```

### Best Practices

1. **Validate all user input** - Never trust user-supplied data
2. **Fail closed** - When in doubt, reject the input
3. **Use allowlists** - Prefer allowlists over blocklists when possible
4. **Validate early** - Check inputs at the entry point
5. **Use type-safe validators** - The security validators return structured results

## URL and SSRF Protection

### Configuration

The URL validator blocks dangerous targets by default:

```typescript
import { validateUrl } from '@n8n/config';

// Default: blocks localhost, private IPs, link-local
const result = validateUrl('http://example.com/api');

// Custom configuration
const result = validateUrl(url, {
  blockLocalhost: true,        // Block 127.0.0.0/8, ::1, etc.
  blockPrivateIPs: true,        // Block 10.0.0.0/8, 192.168.0.0/16, etc.
  blockLinkLocal: true,         // Block 169.254.0.0/16, fe80::/10
  blockedHosts: ['internal.corp'], // Additional blocked hosts
  allowedProtocols: ['https:'], // Only allow HTTPS
});
```

### Workflow Configuration

When configuring HTTP request nodes or webhooks:

1. **Restrict allowed domains** if possible
2. **Use HTTPS only** for external requests
3. **Avoid user-controlled URLs** - prefer dropdown selections
4. **Log all external requests** for audit trails

### Environment Variables

```bash
# Restrict file access to specific directories
N8N_RESTRICT_FILE_ACCESS_TO="/app/data;/app/uploads"

# Block access to n8n config files
N8N_BLOCK_FILE_ACCESS_TO_N8N_FILES=true
```

## Path Traversal Protection

### Using the Validator

Always validate file paths with a base directory:

```typescript
import { validatePathWithinBase } from '@n8n/config';

const basePath = '/app/data/uploads';
const result = validatePathWithinBase(userSuppliedPath, basePath);

if (!result.isValid) {
  throw new Error(`Path traversal detected: ${result.error}`);
}

// Use the resolved path (guaranteed to be within basePath)
const safePath = result.resolvedPath;
```

### Best Practices

1. **Always use canonical path checking** - Don't rely on string checks like `includes('..')`
2. **Set a restrictive base path** - Limit file access to specific directories
3. **Reject absolute paths by default** - Unless explicitly needed
4. **Handle all path separators** - The validator handles both `/` and `\`

## Password and Secret Management

### Password Validation

Enforce strong passwords for user accounts:

```typescript
import { validatePassword } from '@n8n/config';

const result = validatePassword(password, {
  minLength: 12,              // Minimum 12 characters
  requireUppercase: true,
  requireLowercase: true,
  requireDigit: true,
  requireSpecialChar: true,
  checkWeakPasswords: true,   // Check against common weak passwords
});

if (!result.isValid) {
  return { error: result.error };
}

// Show warnings for weak but acceptable passwords
if (result.warnings) {
  console.warn('Password warnings:', result.warnings);
}
```

### Secret Validation

For API keys, tokens, and other secrets:

```typescript
import { validateSecret } from '@n8n/config';

// Secrets should be at least 32 characters with good entropy
const result = validateSecret(apiKey, 32);

if (!result.isValid) {
  throw new Error(`Weak secret: ${result.error}`);
}
```

### Best Practices

1. **Use long secrets** - Minimum 32 characters for API keys/tokens
2. **Generate secrets cryptographically** - Use `crypto.randomBytes()` or similar
3. **Never hardcode secrets** - Use environment variables
4. **Rotate secrets regularly** - Especially after team member departures
5. **Hash passwords** - Use bcrypt, argon2, or scrypt (never MD5/SHA1)

### Environment Variables

```bash
# Use strong encryption keys
N8N_ENCRYPTION_KEY="$(openssl rand -base64 32)"

# Secure JWT secrets
N8N_JWT_SECRET="$(openssl rand -base64 64)"
```

## Email Validation

### Using the Validator

```typescript
import { validateEmail } from '@n8n/config';

const result = validateEmail(email, {
  blockedDomains: ['tempmail.com', 'guerrillamail.com'],
  allowedDomains: ['company.com'], // Optional: restrict to company domain
});

if (!result.isValid) {
  throw new Error(`Invalid email: ${result.error}`);
}

// For multiple emails
import { validateMultipleEmails } from '@n8n/config';

const results = validateMultipleEmails('user1@example.com, user2@example.com');
if (!results.isValid) {
  console.log('Invalid emails:', results.invalidEmails);
}
```

## Content Security Policy (CSP)

### Configuration

Configure CSP via environment variable:

```bash
# Custom CSP configuration (JSON format)
N8N_CONTENT_SECURITY_POLICY='{"script-src": ["'\''self'\''", "https://trusted-cdn.com"]}'

# Use report-only mode for testing
N8N_CONTENT_SECURITY_POLICY_REPORT_ONLY=true
```

### Programmatic Configuration

```typescript
import { getDefaultCSP, mergeCSP, cspDirectivesToString } from '@n8n/config';

// Get secure defaults
const defaultCSP = getDefaultCSP();

// Merge with custom directives
const customCSP = mergeCSP({
  'script-src': ["'self'", 'https://trusted-cdn.com'],
  'frame-ancestors': ["'none'"], // Prevent embedding
});

// Convert to header string
const cspHeader = cspDirectivesToString(customCSP);

res.setHeader('Content-Security-Policy', cspHeader);
```

### Limitations and Migration Path

**Current State**: The default CSP includes `'unsafe-inline'` for backward compatibility with existing workflows.

**Migration Steps**:
1. Audit all inline scripts and styles in workflows
2. Extract inline code to external files or use nonces
3. Test with CSP report-only mode
4. Remove `'unsafe-inline'` from production CSP

## Cookie Security

### Using Secure Defaults

```typescript
import {
  getSessionCookieOptions,
  getCSRFCookieOptions,
  applySecureDefaults,
} from '@n8n/config';

const isProduction = process.env.NODE_ENV === 'production';

// Session cookies
res.cookie('sessionId', sessionId, getSessionCookieOptions(isProduction));

// CSRF tokens
res.cookie('csrf-token', csrfToken, getCSRFCookieOptions(isProduction));

// Custom cookies with secure defaults
const cookieOptions = applySecureDefaults(
  { maxAge: 86400 },    // 1 day
  'general',            // Cookie type
  isProduction
);
res.cookie('preference', value, cookieOptions);
```

### Best Practices

1. **Always set `Secure` in production** - Cookies only sent over HTTPS
2. **Use `HttpOnly` for session cookies** - Prevents XSS cookie theft
3. **Set `SameSite=Lax` or `Strict`** - CSRF protection
4. **Minimize cookie lifetimes** - Shorter is more secure
5. **Use `__Host-` prefix** - For maximum security (requires Secure, no Domain, Path=/)

## HTTPS and TLS

### Configuration

```bash
# Enable HTTPS
N8N_PROTOCOL=https
N8N_SSL_KEY="/path/to/private-key.pem"
N8N_SSL_CERT="/path/to/certificate.pem"

# Behind a reverse proxy
N8N_PROXY_HOPS=1
```

### Best Practices

1. **Use HTTPS in production** - Always encrypt traffic
2. **Use valid certificates** - From Let's Encrypt or a trusted CA
3. **Configure TLS 1.2+** - Disable older protocols
4. **Enable HSTS** - Configured by default in production
5. **Use strong cipher suites** - Prefer forward secrecy

## Environment Configuration

### Production Checklist

```bash
# General
NODE_ENV=production
N8N_PROTOCOL=https
N8N_HOST=your-domain.com

# Security
N8N_ENCRYPTION_KEY="$(openssl rand -base64 32)"
N8N_JWT_SECRET="$(openssl rand -base64 64)"
N8N_BLOCK_FILE_ACCESS_TO_N8N_FILES=true
N8N_RESTRICT_FILE_ACCESS_TO="/app/data;/app/uploads"

# Cookie Security (via CSP config)
N8N_CONTENT_SECURITY_POLICY='{"frame-ancestors": ["'\''none'\''"]}' # Prevent embedding

# Database
# Use strong database passwords
# Enable SSL/TLS for database connections

# Disable unnecessary features
N8N_HIDE_USAGE_PAGE=false # Set to true if needed
```

## Monitoring and Auditing

### Security Logging

Enable detailed logging for security events:

```bash
N8N_LOG_LEVEL=info
N8N_LOG_OUTPUT=file
N8N_LOG_FILE_LOCATION="/var/log/n8n"
```

### Regular Security Audits

1. **Review access logs** - Look for suspicious patterns
2. **Monitor failed login attempts** - Configure rate limiting
3. **Audit user permissions** - Follow principle of least privilege
4. **Review workflow changes** - Track who modified what
5. **Check for outdated dependencies** - Run `pnpm audit` regularly

### Automated Security Scanning

Run security scans regularly:

```bash
# Dependency vulnerabilities
pnpm audit

# Run security tests
pnpm test --filter @n8n/config

# Check for leaked secrets (use git-secrets or similar)
git secrets --scan
```

## Reporting Security Issues

If you discover a security vulnerability:

1. **Do NOT open a public issue**
2. Report via the [Vulnerability Disclosure Program](https://n8n.notion.site/n8n-vulnerability-disclosure-program)
3. Include detailed steps to reproduce
4. Wait for acknowledgment before public disclosure

## Resources

- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)

---

**Last Updated**: 2025-11-22  
**Version**: 1.0.0
