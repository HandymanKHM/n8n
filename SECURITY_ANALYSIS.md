# Security Analysis and Remediation Status

This document tracks the security review findings, implemented mitigations, and remaining work items for the n8n platform.

## Overview

This security review focuses on common web application vulnerabilities and secure-by-default configurations. The review covers input validation, SSRF protection, path traversal prevention, secure defaults for cookies and CSP, and HTML sanitization.

## Implemented Security Controls

### ✅ Input Validators (packages/@n8n/config/src/validators)

Security validators have been implemented to protect against common attack vectors:

1. **URL/SSRF Validator** (`url-validator.ts`)
   - Blocks localhost and loopback addresses (127.0.0.0/8, ::1, ::ffff:127.0.0.1, 0.0.0.0)
   - Blocks private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
   - Blocks link-local addresses (169.254.0.0/16, fe80::/10)
   - Supports custom blocked/allowed hosts and protocols
   - Uses Node's `net.isIP()` for reliable IP classification
   - Defaults to fail-closed (blocks by default)

2. **Path Traversal Validator** (`path-validator.ts`)
   - Uses canonical path resolution with `path.resolve()`
   - Validates paths are within allowed base directory
   - Rejects null bytes (\\0) in paths
   - Handles platform-specific path separators
   - Prevents sophisticated traversal attempts (../../../, encoded paths, etc.)

3. **Password/Secret Strength Validator** (`password-validator.ts`)
   - Curated list of 40+ common weak passwords
   - Pattern detection (sequential, keyboard walks, repeated characters)
   - Configurable length and character requirements
   - Separate validation for API secrets/tokens with higher entropy requirements
   - Explicitly NOT a comprehensive breach database check (documented limitation)

4. **Email Validator** (`email-validator.ts`)
   - RFC 5322 compliant regex pattern
   - Blocks localhost and IP address domains
   - Supports domain allowlists/blocklists
   - Validates email structure (no consecutive dots, etc.)
   - Handles multiple email validation

### ✅ Secure Defaults (packages/@n8n/config/src/secure-defaults)

Secure default configurations are provided for security-critical settings:

1. **Content Security Policy** (`csp-defaults.ts`)
   - **Known Limitation**: Includes `'unsafe-inline'` for backward compatibility
   - **Rationale**: Existing n8n workflows rely on inline scripts/styles
   - **Mitigation Plan**: Document as technical debt; future migration to nonce/hash-based CSP
   - Blocks `<object>` and `<embed>` tags
   - Restricts frame ancestors (clickjacking protection)
   - Supports custom CSP via `N8N_CONTENT_SECURITY_POLICY` env var

2. **Cookie Security** (`cookie-defaults.ts`)
   - **Session cookies**: `HttpOnly=true`, `Secure=true` (production), `SameSite=Lax`
   - **CSRF tokens**: `SameSite=Strict`, `Secure=true` (production)
   - **General cookies**: `SameSite=Lax` for CSRF protection
   - Validation function warns about insecure configurations
   - All defaults configurable per cookie type

### ✅ Comprehensive Test Coverage

All validators and secure defaults have extensive test suites covering:
- Valid inputs and edge cases
- Attack vectors (SSRF, traversal, weak passwords, etc.)
- Configuration options
- Platform-specific behavior
- Real-world scenarios

## Existing Security Controls (Already in Repository)

### HTML Sanitization

The repository already has XSS protection in place:
- **packages/@n8n/db**: `no-xss.validator.ts` using the `xss` library
- **packages/cli**: `webhook-request-sanitizer.ts` for webhook input sanitization
- **Recommendation**: Continue using library-based sanitization (not regex-based)

### Origin Validation

Strong origin validation exists:
- **packages/cli**: `origin-validator.ts` with RFC 7239 Forwarded header support
- Handles proxy headers correctly
- IPv6 bracket normalization

## Security Workflow

### ✅ Workflow Configuration

A security scanning workflow is configured at `.github/workflows/security-scan.yml`:

**Current Status**: To be created/updated in this PR

**Planned Components**:
1. Node.js/pnpm version consistency (from main repo config)
2. Dependency vulnerability scanning (`pnpm audit`)
3. Security validator tests
4. Secret scanning (GitHub native)
5. License compliance checking
6. SARIF report generation

## Open Security Items

### High Priority

1. **Nonce-based CSP Migration**
   - Current: CSP includes `'unsafe-inline'` for compatibility
   - Target: Migrate to nonce or hash-based CSP
   - Impact: Eliminates inline script/style attack vector
   - Effort: Medium (requires workflow editor changes)

2. **Password Breach Database Integration**
   - Current: Basic weak password list (40+ entries)
   - Target: Integrate with Have I Been Pwned API or similar
   - Impact: Prevents use of known breached passwords
   - Effort: Low to Medium

3. **Rate Limiting for Validators**
   - Current: No rate limiting on validation endpoints
   - Target: Add rate limiting to prevent DoS via validator abuse
   - Impact: Prevents resource exhaustion
   - Effort: Low

### Medium Priority

4. **Hostname DNS Resolution for SSRF**
   - Current: IP-based checks only
   - Target: Resolve hostnames to IPs before making requests
   - Impact: Prevents DNS rebinding attacks
   - Effort: Medium (async validation required)

5. **File Upload Validation**
   - Current: Basic type checking
   - Target: Magic byte validation, virus scanning integration
   - Impact: Prevents malicious file uploads
   - Effort: Medium

6. **Security Headers Middleware**
   - Current: CSP configured, other headers may be ad-hoc
   - Target: Centralized security headers (HSTS, X-Frame-Options, etc.)
   - Impact: Defense in depth
   - Effort: Low

### Low Priority

7. **Security Audit Logging**
   - Current: Standard application logging
   - Target: Dedicated security event logging
   - Impact: Better incident response and forensics
   - Effort: Medium

8. **Automated Security Testing**
   - Current: Unit tests for validators
   - Target: Integration tests with OWASP ZAP or similar
   - Impact: Continuous security validation
   - Effort: High

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [MDN Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [MDN HTTP Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)

## Review Schedule

This document should be reviewed and updated:
- After each security-related PR merge
- Quarterly for open item prioritization
- After security incidents or disclosures
- Before major releases

---

**Last Updated**: 2025-11-22  
**Status**: Initial security review implementation
