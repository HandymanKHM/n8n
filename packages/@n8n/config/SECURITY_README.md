# @n8n/config - Security Module

This package provides security validators and secure defaults for the n8n platform.

## Overview

The `@n8n/config` package includes:

- **Security Validators**: Input validation for SSRF, path traversal, passwords, and emails
- **Secure Defaults**: Secure configurations for CSP and cookies
- **Configuration Management**: Type-safe environment variable handling

## Security Validators

### URL Validator (SSRF Protection)

Protects against Server-Side Request Forgery by blocking requests to internal networks:

```typescript
import { validateUrl } from '@n8n/config';

const result = validateUrl('http://example.com/api');
if (!result.isValid) {
  throw new Error(result.error);
}
```

**Blocked by default:**
- Localhost (127.0.0.0/8, ::1, ::ffff:127.0.0.1)
- Private IPs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Link-local (169.254.0.0/16, fe80::/10)
- IPv6 private ranges (fc00::/7)

### Path Validator (Traversal Protection)

Prevents path traversal attacks using canonical path resolution:

```typescript
import { validatePathWithinBase } from '@n8n/config';

const result = validatePathWithinBase(userPath, '/safe/directory');
if (!result.isValid) {
  throw new Error(result.error);
}

// Use the resolved path (guaranteed safe)
const safePath = result.resolvedPath;
```

### Password Validator

Enforces password strength requirements:

```typescript
import { validatePassword } from '@n8n/config';

const result = validatePassword(password, {
  minLength: 12,
  requireUppercase: true,
  requireDigit: true,
  requireSpecialChar: true,
});

if (!result.isValid) {
  return { error: result.error };
}

// Show warnings for weak but acceptable passwords
if (result.warnings) {
  console.warn(result.warnings);
}
```

**Checks for:**
- Minimum length
- Character requirements (uppercase, lowercase, digits, special)
- Common weak passwords (40+ patterns)
- Sequential patterns (123, abc, qwerty)
- Repeated characters (aaaa, 1111)

### Secret Validator

Validates API keys, tokens, and other secrets:

```typescript
import { validateSecret } from '@n8n/config';

const result = validateSecret(apiKey, 32); // Min 32 chars
if (!result.isValid) {
  throw new Error(result.error);
}
```

**Checks for:**
- Minimum length (default: 32 characters)
- Placeholder values (example, sample, changeme, etc.)
- Character entropy (at least 10 unique characters)

### Email Validator

Validates email addresses with RFC 5322 compliance:

```typescript
import { validateEmail } from '@n8n/config';

const result = validateEmail(email, {
  blockedDomains: ['tempmail.com'],
  allowedDomains: ['company.com'], // Optional restriction
});

if (!result.isValid) {
  throw new Error(result.error);
}
```

## Secure Defaults

### Content Security Policy (CSP)

```typescript
import {
  getDefaultCSP,
  cspDirectivesToString,
  mergeCSP,
} from '@n8n/config';

// Get secure defaults
const csp = getDefaultCSP();

// Merge with custom directives
const customCSP = mergeCSP({
  'script-src': ["'self'", 'https://trusted-cdn.com'],
});

// Convert to header string
const cspHeader = cspDirectivesToString(customCSP);

res.setHeader('Content-Security-Policy', cspHeader);
```

**Default CSP includes:**
- `default-src 'self'` - Restrict to same origin
- `object-src 'none'` - Block plugins
- `frame-ancestors 'self'` - Clickjacking protection
- ⚠️ `'unsafe-inline'` - Included for backward compatibility (see limitations)

**Known Limitation:** The default CSP includes `'unsafe-inline'` for backward compatibility with existing n8n workflows. This should be migrated to nonce-based CSP in future versions.

### Cookie Security

```typescript
import {
  getSessionCookieOptions,
  getCSRFCookieOptions,
  applySecureDefaults,
  validateCookieOptions,
} from '@n8n/config';

const isProduction = process.env.NODE_ENV === 'production';

// Session cookies
res.cookie('session', sessionId, getSessionCookieOptions(isProduction));
// Result: { httpOnly: true, secure: true, sameSite: 'Lax' }

// CSRF tokens
res.cookie('csrf', token, getCSRFCookieOptions(isProduction));
// Result: { httpOnly: false, secure: true, sameSite: 'Strict' }

// Apply defaults to custom cookies
const options = applySecureDefaults({ maxAge: 86400 }, 'general', isProduction);

// Validate cookie options
const warnings = validateCookieOptions(options, isProduction);
if (warnings.length > 0) {
  console.warn('Cookie security warnings:', warnings);
}
```

**Cookie defaults:**
- Session: `httpOnly=true, secure=true (prod), sameSite=Lax`
- CSRF: `httpOnly=false, secure=true (prod), sameSite=Strict`
- General: `httpOnly=false, secure=true (prod), sameSite=Lax`

## Testing

Run the security validator tests:

```bash
# From repository root
pnpm test --filter @n8n/config

# From package directory
cd packages/@n8n/config
pnpm test

# Watch mode
pnpm test:dev
```

## API Reference

### Validators

- `validateUrl(url: string, options?: UrlValidationOptions): UrlValidationResult`
- `validatePath(path: string, options?: PathValidationOptions): PathValidationResult`
- `validatePathWithinBase(path: string, basePath: string): PathValidationResult`
- `validatePassword(password: string, options?: PasswordValidationOptions): PasswordValidationResult`
- `validateSecret(secret: string, minLength?: number): PasswordValidationResult`
- `validateEmail(email: string, options?: EmailValidationOptions): EmailValidationResult`
- `validateMultipleEmails(emails: string, separator?: string | RegExp, options?: EmailValidationOptions)`

### Secure Defaults

- `getDefaultCSP(): CSPDirectives`
- `cspDirectivesToString(directives: CSPDirectives): string`
- `mergeCSP(customDirectives: Partial<CSPDirectives>): CSPDirectives`
- `parseCSPString(cspString: string): Partial<CSPDirectives>`
- `getSecureCookieDefaults(isProduction?: boolean): SecureCookieDefaults`
- `getSessionCookieOptions(isProduction?: boolean, maxAge?: number): CookieOptions`
- `getCSRFCookieOptions(isProduction?: boolean): CookieOptions`
- `applySecureDefaults(options: Partial<CookieOptions>, cookieType?: string, isProduction?: boolean): CookieOptions`
- `validateCookieOptions(options: CookieOptions, isProduction?: boolean): string[]`

## Security Best Practices

1. **Always validate user input** - Use the appropriate validator for your use case
2. **Fail closed** - Reject invalid input by default
3. **Use allowlists** - Prefer allowlists over blocklists when possible
4. **Apply secure defaults** - Use the provided secure defaults for CSP and cookies
5. **Test thoroughly** - Write tests for your security-critical code paths

## Limitations

### CSP 'unsafe-inline'

The default CSP includes `'unsafe-inline'` for script-src and style-src to maintain backward compatibility with existing n8n workflows. This is a known security limitation.

**Migration path:**
1. Audit inline scripts/styles in workflows
2. Extract to external files or use nonces
3. Test with CSP report-only mode
4. Remove 'unsafe-inline' from production

### Password Validator Scope

The password validator checks against a curated list of ~40 common weak passwords. It does NOT:
- Check against breach databases (e.g., Have I Been Pwned)
- Calculate Shannon entropy
- Perform deep dictionary checks

For production systems, consider integrating additional password validation services.

## Contributing

When adding new validators or defaults:

1. Follow fail-closed principles (reject by default)
2. Write comprehensive tests (including attack vectors)
3. Document limitations clearly
4. Update this README with examples

## Resources

- [Repository Security Documentation](../../SECURITY_BEST_PRACTICES.md)
- [HTML Sanitization Guide](../../HTML_SANITIZATION_SECURITY.md)
- [Security Analysis](../../SECURITY_ANALYSIS.md)
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)

## License

See the main [LICENSE](../../LICENSE.md) file in the repository root.

---

**Package Version**: 1.60.0  
**Last Updated**: 2025-11-22  
**Maintainers**: n8n Security Team
