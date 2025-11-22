# HTML Sanitization Security Guide

## Overview

HTML sanitization is the process of removing or neutralizing potentially malicious HTML/JavaScript code from user input to prevent Cross-Site Scripting (XSS) attacks. This document explains n8n's approach to HTML sanitization and provides guidance on secure implementation.

## ⚠️ Critical Warning

**NEVER rely on regex-based HTML sanitization for security-critical operations.**

Regular expressions cannot parse HTML correctly due to its recursive, context-dependent nature. Any regex-based "sanitizer" can be bypassed with creative input and should be considered a cosmetic filter at best, not a security control.

## Existing Sanitization in n8n

### ✅ Library-Based Sanitization (Secure)

The n8n codebase currently uses proper library-based sanitization:

1. **XSS Library** (`packages/@n8n/db/src/utils/validators/no-xss.validator.ts`)
   ```typescript
   import xss from 'xss';
   
   // This uses the 'xss' library, which is a proper HTML sanitizer
   const sanitized = xss(userInput, {
     whiteList: {}, // no tags are allowed
   });
   ```

2. **Webhook Request Sanitizer** (`packages/cli/src/webhooks/webhook-request-sanitizer.ts`)
   - Sanitizes webhook request data
   - Uses the `xss` library under the hood

### ❌ Regex-Based Sanitization (Insecure)

**Do NOT create new regex-based sanitizers.** Any existing regex-based HTML processing should be:

1. Clearly marked as non-security-critical (display formatting only)
2. Never used for input that will be rendered in HTML contexts
3. Replaced with library-based sanitization for any security-sensitive use case

## Recommended Sanitization Approaches

### For Server-Side (Node.js)

Use one of these established libraries:

1. **xss** (Current choice in n8n)
   ```typescript
   import xss from 'xss';
   
   const clean = xss(userInput, {
     whiteList: {
       a: ['href', 'title'],
       b: [],
       i: [],
       strong: [],
     },
     stripIgnoreTag: true,
     stripIgnoreTagBody: ['script', 'style'],
   });
   ```

2. **DOMPurify** (with jsdom for server-side)
   ```typescript
   import createDOMPurify from 'dompurify';
   import { JSDOM } from 'jsdom';
   
   const window = new JSDOM('').window;
   const DOMPurify = createDOMPurify(window);
   
   const clean = DOMPurify.sanitize(userInput, {
     ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
     ALLOWED_ATTR: ['href'],
   });
   ```

3. **sanitize-html**
   ```typescript
   import sanitizeHtml from 'sanitize-html';
   
   const clean = sanitizeHtml(userInput, {
     allowedTags: ['b', 'i', 'em', 'strong', 'a'],
     allowedAttributes: {
       'a': ['href']
     },
   });
   ```

### For Client-Side (Browser)

1. **DOMPurify** (Preferred)
   ```typescript
   import DOMPurify from 'dompurify';
   
   const clean = DOMPurify.sanitize(userInput);
   ```

2. **Native Sanitizer API** (Future - limited browser support)
   ```typescript
   const sanitizer = new Sanitizer();
   const clean = sanitizer.sanitizeFor('div', userInput);
   ```

## Implementation Guidelines

### When to Sanitize

Sanitize HTML content when:

1. ✅ Displaying user-generated content in HTML context
2. ✅ Storing user input that will later be rendered as HTML
3. ✅ Processing webhook payloads that may contain HTML
4. ✅ Rendering email content
5. ✅ Displaying workflow execution results

### When NOT to Sanitize

Do NOT sanitize when:

1. ❌ Input will be displayed as plain text (use proper text encoding instead)
2. ❌ Input will only be used in non-HTML contexts (JSON, databases, etc.)
3. ❌ Input is already properly escaped by the rendering framework (e.g., Vue templates with `{{ }}`)

### Defense in Depth

HTML sanitization should be ONE layer in a defense-in-depth strategy:

```
User Input
    ↓
[1. Input Validation] ← Validate expected format
    ↓
[2. Sanitization] ← Remove malicious content
    ↓
[3. Context-Aware Encoding] ← Encode for output context
    ↓
[4. Content Security Policy] ← Browser-level protection
    ↓
Display
```

## Common Pitfalls

### ❌ Pitfall 1: Sanitizing After Rendering

```typescript
// WRONG: XSS already occurred
element.innerHTML = userInput;
element.innerHTML = xss(element.innerHTML);

// RIGHT: Sanitize before rendering
element.innerHTML = xss(userInput);
```

### ❌ Pitfall 2: Double Encoding

```typescript
// WRONG: Double encoding breaks display
const encoded = escapeHtml(userInput);
const sanitized = xss(encoded); // Now contains &lt; instead of <

// RIGHT: Sanitize, then let the framework handle encoding
const sanitized = xss(userInput);
// Vue/React will automatically escape when rendering
```

### ❌ Pitfall 3: Allowlist Too Permissive

```typescript
// WRONG: Allows dangerous attributes
const clean = xss(userInput, {
  whiteList: {
    img: ['src', 'onerror'], // onerror is dangerous!
    a: ['href', 'onclick'],   // onclick is dangerous!
  },
});

// RIGHT: Only allow safe attributes
const clean = xss(userInput, {
  whiteList: {
    img: ['src', 'alt'],
    a: ['href', 'title'],
  },
});
```

### ❌ Pitfall 4: Trusting "Sanitized" Data

```typescript
// WRONG: Assuming sanitization is perfect
const sanitized = xss(userInput);
eval(sanitized); // NEVER EVER

// RIGHT: Treat ALL user input as untrusted
const sanitized = xss(userInput);
// Only use in HTML rendering contexts
element.innerHTML = sanitized;
```

## Configuration Examples

### Strict Sanitization (Recommended Default)

```typescript
import xss from 'xss';

const strictOptions = {
  whiteList: {}, // No tags allowed
  stripIgnoreTag: true,
  stripIgnoreTagBody: ['script', 'style'],
};

const clean = xss(userInput, strictOptions);
// Result: All HTML removed, only text remains
```

### Allow Safe Formatting Tags

```typescript
import xss from 'xss';

const formattingOptions = {
  whiteList: {
    b: [],
    i: [],
    em: [],
    strong: [],
    u: [],
    p: [],
    br: [],
  },
  stripIgnoreTag: true,
  stripIgnoreTagBody: ['script', 'style'],
};

const clean = xss(userInput, formattingOptions);
// Result: Basic formatting allowed, scripts removed
```

### Allow Links (With URL Validation)

```typescript
import xss from 'xss';
import { validateUrl } from '@n8n/config';

const linkOptions = {
  whiteList: {
    a: ['href', 'title'],
  },
  stripIgnoreTag: true,
  stripIgnoreTagBody: ['script', 'style'],
  onTagAttr: (tag, name, value) => {
    // Validate href attributes
    if (tag === 'a' && name === 'href') {
      const result = validateUrl(value);
      if (!result.isValid) {
        return ''; // Remove invalid URLs
      }
    }
  },
};

const clean = xss(userInput, linkOptions);
// Result: Links allowed, but URLs are validated
```

## Testing Sanitization

### Test Cases

Always test your sanitization with these vectors:

```typescript
const xssVectors = [
  '<script>alert("XSS")</script>',
  '<img src=x onerror=alert("XSS")>',
  '<svg onload=alert("XSS")>',
  'javascript:alert("XSS")',
  '<iframe src="javascript:alert(\'XSS\')">',
  '<body onload=alert("XSS")>',
  '<input onfocus=alert("XSS") autofocus>',
  '<marquee onstart=alert("XSS")>',
  '"><script>alert(String.fromCharCode(88,83,83))</script>',
  '<IMG SRC="javascript:alert(\'XSS\');">',
];

xssVectors.forEach(vector => {
  const result = xss(vector, strictOptions);
  console.log(`Input: ${vector}`);
  console.log(`Output: ${result}`);
  console.log(`Safe: ${!result.includes('script') && !result.includes('onerror')}`);
});
```

## Vue.js Integration (n8n Frontend)

Vue.js automatically escapes content by default:

```vue
<template>
  <!-- SAFE: Vue escapes by default -->
  <div>{{ userInput }}</div>
  
  <!-- DANGEROUS: v-html bypasses escaping -->
  <div v-html="userInput"></div>
  
  <!-- SAFE: Sanitize before using v-html -->
  <div v-html="sanitizedInput"></div>
</template>

<script>
import DOMPurify from 'dompurify';

export default {
  computed: {
    sanitizedInput() {
      return DOMPurify.sanitize(this.userInput);
    }
  }
}
</script>
```

## Migrating from Regex to Library

If you find regex-based HTML sanitization in the codebase:

```typescript
// BEFORE: Regex-based (insecure)
const sanitized = userInput.replace(/<script[^>]*>.*?<\/script>/gi, '');

// AFTER: Library-based (secure)
import xss from 'xss';
const sanitized = xss(userInput, { whiteList: {} });
```

## References

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP DOM Based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [DOMPurify Documentation](https://github.com/cure53/DOMPurify)
- [XSS Library Documentation](https://github.com/leizongmin/js-xss)
- [Content Security Policy Guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

## Quick Reference

| Scenario | Recommendation |
|----------|----------------|
| Display user HTML safely | Use DOMPurify or xss library |
| Display user text safely | Use framework's text binding (Vue `{{ }}`) |
| Store user HTML | Sanitize on input AND output |
| Allow formatted text | Allowlist safe tags (b, i, em, strong) |
| Allow links | Allowlist `<a>` + validate URLs with `validateUrl()` |
| Custom sanitization | Extend existing library, don't write regex |
| Testing sanitization | Use OWASP XSS vectors |

---

**Last Updated**: 2025-11-22  
**Status**: Production guidance  
**Applies to**: All n8n components handling HTML
