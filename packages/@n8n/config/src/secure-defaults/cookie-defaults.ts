/**
 * Secure default cookie configuration.
 * 
 * These defaults ensure cookies are configured securely by default,
 * protecting against common attacks like session hijacking, CSRF, and XSS.
 * 
 * See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
 */

export interface CookieOptions {
	/**
	 * Whether the cookie is only sent over HTTPS
	 * @default true (in production)
	 */
	secure?: boolean;

	/**
	 * Whether the cookie is inaccessible to JavaScript (XSS protection)
	 * @default true (for session/auth cookies)
	 */
	httpOnly?: boolean;

	/**
	 * Controls whether the cookie is sent with cross-site requests
	 * - 'Strict': Cookie is only sent in a first-party context
	 * - 'Lax': Cookie is sent with top-level navigations and same-site requests
	 * - 'None': Cookie is sent with all requests (requires Secure)
	 * @default 'Lax'
	 */
	sameSite?: 'Strict' | 'Lax' | 'None';

	/**
	 * Maximum age of the cookie in seconds
	 */
	maxAge?: number;

	/**
	 * Expiration date of the cookie
	 */
	expires?: Date;

	/**
	 * Path where the cookie is valid
	 * @default '/'
	 */
	path?: string;

	/**
	 * Domain where the cookie is valid
	 */
	domain?: string;
}

export interface SecureCookieDefaults {
	/**
	 * Defaults for session/authentication cookies
	 */
	session: CookieOptions;

	/**
	 * Defaults for regular application cookies
	 */
	general: CookieOptions;

	/**
	 * Defaults for CSRF tokens
	 */
	csrf: CookieOptions;
}

/**
 * Returns secure default cookie options based on environment.
 * 
 * @param isProduction - Whether the application is running in production
 * @returns Secure cookie defaults
 */
export function getSecureCookieDefaults(isProduction: boolean = true): SecureCookieDefaults {
	return {
		// Session/authentication cookies - most restrictive
		session: {
			httpOnly: true,  // Prevent XSS attacks from stealing session
			secure: isProduction,  // HTTPS only in production
			sameSite: 'Lax',  // Balance between security and usability
			path: '/',
		},

		// General application cookies
		general: {
			httpOnly: false,  // May need to be accessible to JavaScript
			secure: isProduction,  // HTTPS only in production
			sameSite: 'Lax',  // CSRF protection
			path: '/',
		},

		// CSRF token cookies
		csrf: {
			httpOnly: false,  // Must be readable by JavaScript to include in requests
			secure: isProduction,  // HTTPS only in production
			sameSite: 'Strict',  // Strict CSRF protection
			path: '/',
		},
	};
}

/**
 * Creates secure cookie options for a session cookie.
 * 
 * @param isProduction - Whether running in production
 * @param maxAge - Optional max age in seconds
 * @returns Secure session cookie options
 */
export function getSessionCookieOptions(
	isProduction: boolean = true,
	maxAge?: number,
): CookieOptions {
	const defaults = getSecureCookieDefaults(isProduction);
	
	return {
		...defaults.session,
		...(maxAge ? { maxAge } : {}),
	};
}

/**
 * Creates secure cookie options for a CSRF token.
 * 
 * @param isProduction - Whether running in production
 * @returns Secure CSRF cookie options
 */
export function getCSRFCookieOptions(isProduction: boolean = true): CookieOptions {
	const defaults = getSecureCookieDefaults(isProduction);
	return defaults.csrf;
}

/**
 * Validates cookie options for security issues.
 * Returns warnings for potentially insecure configurations.
 * 
 * @param options - Cookie options to validate
 * @param isProduction - Whether running in production
 * @returns Array of security warnings
 */
export function validateCookieOptions(
	options: CookieOptions,
	isProduction: boolean = true,
): string[] {
	const warnings: string[] = [];

	// Check for secure flag in production
	if (isProduction && !options.secure) {
		warnings.push(
			'Cookie "secure" flag is not set in production. Cookies will be sent over unencrypted HTTP.',
		);
	}

	// Check for SameSite=None without Secure
	if (options.sameSite === 'None' && !options.secure) {
		warnings.push(
			'Cookie with SameSite=None must also have Secure flag set. ' +
			'This configuration will be rejected by modern browsers.',
		);
	}

	// Check for missing SameSite (defaults to Lax in modern browsers, but be explicit)
	if (!options.sameSite) {
		warnings.push(
			'Cookie SameSite attribute is not set. Modern browsers default to "Lax", ' +
			'but explicit configuration is recommended.',
		);
	}

	// Warn about httpOnly for session cookies
	if (!options.httpOnly && isProduction) {
		warnings.push(
			'Cookie "httpOnly" flag is not set. If this is a session cookie, ' +
			'it may be vulnerable to XSS attacks.',
		);
	}

	// Check for overly permissive domain
	if (options.domain && (options.domain === '*' || options.domain.startsWith('.'))) {
		warnings.push(
			'Cookie domain is set to a wildcard or subdomain pattern. ' +
			'Ensure this is intentional and necessary.',
		);
	}

	return warnings;
}

/**
 * Applies secure defaults to cookie options.
 * Fills in missing security-critical options with secure defaults.
 * 
 * @param options - Partial cookie options
 * @param cookieType - Type of cookie ('session', 'general', or 'csrf')
 * @param isProduction - Whether running in production
 * @returns Complete cookie options with secure defaults
 */
export function applySecureDefaults(
	options: Partial<CookieOptions>,
	cookieType: 'session' | 'general' | 'csrf' = 'general',
	isProduction: boolean = true,
): CookieOptions {
	const defaults = getSecureCookieDefaults(isProduction)[cookieType];
	
	return {
		...defaults,
		...options,
	};
}
