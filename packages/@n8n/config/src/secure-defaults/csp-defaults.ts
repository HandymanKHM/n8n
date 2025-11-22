/**
 * Secure default Content Security Policy configuration.
 * 
 * IMPORTANT: These defaults include 'unsafe-inline' for backward compatibility
 * with existing n8n deployments. This is documented as a known limitation.
 * 
 * FUTURE IMPROVEMENT: Migrate to nonce-based or hash-based CSP to remove 'unsafe-inline'.
 * See: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
 * 
 * For custom CSP configuration, see the N8N_CONTENT_SECURITY_POLICY environment variable
 * in the security config.
 */

export interface CSPDirectives {
	/**
	 * Defines valid sources for JavaScript
	 */
	'script-src'?: string[];
	
	/**
	 * Defines valid sources for stylesheets
	 */
	'style-src'?: string[];
	
	/**
	 * Defines valid sources for images
	 */
	'img-src'?: string[];
	
	/**
	 * Defines valid sources for fonts
	 */
	'font-src'?: string[];
	
	/**
	 * Defines valid sources for <object>, <embed>, <applet>
	 */
	'object-src'?: string[];
	
	/**
	 * Defines valid sources for XMLHttpRequest, fetch, etc.
	 */
	'connect-src'?: string[];
	
	/**
	 * Defines valid sources for <frame> and <iframe>
	 */
	'frame-src'?: string[];
	
	/**
	 * Restricts which URLs can be loaded in nested browsing contexts
	 */
	'frame-ancestors'?: string[];
	
	/**
	 * Defines valid sources for Worker, SharedWorker, or ServiceWorker scripts
	 */
	'worker-src'?: string[];
	
	/**
	 * Defines valid sources for form submissions
	 */
	'form-action'?: string[];
	
	/**
	 * Fallback for other directives
	 */
	'default-src'?: string[];
	
	/**
	 * Defines valid sources for web app manifests
	 */
	'manifest-src'?: string[];
	
	/**
	 * Defines valid sources for audio and video
	 */
	'media-src'?: string[];
	
	/**
	 * Instructs user agents to rewrite URL schemes
	 */
	'upgrade-insecure-requests'?: boolean;
	
	/**
	 * Instructs the user agent to treat all site content as https
	 */
	'block-all-mixed-content'?: boolean;
}

/**
 * Returns secure default CSP directives for n8n.
 * 
 * These defaults are intentionally strict but include 'unsafe-inline' for
 * backward compatibility. This is a known limitation that should be addressed
 * by migrating to nonce-based CSP in future versions.
 * 
 * @returns CSP directives object
 */
export function getDefaultCSP(): CSPDirectives {
	return {
		// Default fallback - restrict to self and explicitly allowed sources
		'default-src': ["'self'"],
		
		// Scripts: Allow self and inline scripts (TODO: migrate to nonces)
		// WARNING: 'unsafe-inline' allows inline scripts, which can be a security risk
		// This is included for backward compatibility with existing workflows
		'script-src': ["'self'", "'unsafe-inline'"],
		
		// Styles: Allow self and inline styles (TODO: migrate to nonces/hashes)
		// WARNING: 'unsafe-inline' allows inline styles
		// This is included for backward compatibility
		'style-src': ["'self'", "'unsafe-inline'"],
		
		// Images: Allow self, data URIs (for inline images), and https
		'img-src': ["'self'", 'data:', 'https:'],
		
		// Fonts: Allow self and data URIs
		'font-src': ["'self'", 'data:'],
		
		// Objects: Disallow all plugins
		'object-src': ["'none'"],
		
		// AJAX/WebSocket: Allow self
		'connect-src': ["'self'"],
		
		// Frames: Allow self
		'frame-src': ["'self'"],
		
		// Frame ancestors: Restrict embedding (clickjacking protection)
		'frame-ancestors': ["'self'"],
		
		// Workers: Allow self
		'worker-src': ["'self'", 'blob:'],
		
		// Forms: Allow self
		'form-action': ["'self'"],
		
		// Web app manifest: Allow self
		'manifest-src': ["'self'"],
		
		// Media: Allow self
		'media-src': ["'self'"],
	};
}

/**
 * Converts CSP directives object to a header string value.
 * 
 * @param directives - CSP directives object
 * @returns CSP header string
 */
export function cspDirectivesToString(directives: CSPDirectives): string {
	const parts: string[] = [];
	
	for (const [key, value] of Object.entries(directives)) {
		if (value === true) {
			// Boolean directives (e.g., upgrade-insecure-requests)
			parts.push(key);
		} else if (Array.isArray(value) && value.length > 0) {
			// Array directives
			parts.push(`${key} ${value.join(' ')}`);
		}
	}
	
	return parts.join('; ');
}

/**
 * Merges custom CSP directives with defaults.
 * Custom directives override defaults for the same directive.
 * 
 * @param customDirectives - Custom CSP directives
 * @returns Merged CSP directives
 */
export function mergeCSP(customDirectives: Partial<CSPDirectives>): CSPDirectives {
	const defaults = getDefaultCSP();
	
	// Merge objects, with custom directives overriding defaults
	return {
		...defaults,
		...customDirectives,
	};
}

/**
 * Parses a CSP header string into directives object.
 * This is useful for parsing the N8N_CONTENT_SECURITY_POLICY env var.
 * 
 * @param cspString - CSP header string
 * @returns CSP directives object
 */
export function parseCSPString(cspString: string): Partial<CSPDirectives> {
	if (!cspString || typeof cspString !== 'string') {
		return {};
	}
	
	const directives: Partial<CSPDirectives> = {};
	const parts = cspString.split(';').map(s => s.trim()).filter(s => s.length > 0);
	
	for (const part of parts) {
		const [directive, ...values] = part.split(/\s+/);
		if (!directive) continue;
		
		const key = directive as keyof CSPDirectives;
		
		// Check if it's a boolean directive
		if (values.length === 0) {
			directives[key] = true as any;
		} else {
			directives[key] = values as any;
		}
	}
	
	return directives;
}
