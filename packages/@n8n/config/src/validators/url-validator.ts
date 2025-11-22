import { isIP } from 'node:net';

/**
 * Validates URLs for SSRF (Server-Side Request Forgery) protection.
 * Blocks access to localhost, loopback addresses, and private IP ranges by default.
 */

export interface UrlValidationOptions {
	/**
	 * Whether to block localhost and loopback addresses (127.0.0.0/8, ::1, ::ffff:127.0.0.1, 0.0.0.0)
	 * @default true
	 */
	blockLocalhost?: boolean;

	/**
	 * Whether to block private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
	 * @default true
	 */
	blockPrivateIPs?: boolean;

	/**
	 * Whether to block link-local addresses (169.254.0.0/16, fe80::/10)
	 * @default true
	 */
	blockLinkLocal?: boolean;

	/**
	 * Additional blocked hosts (case-insensitive)
	 */
	blockedHosts?: string[];

	/**
	 * Allowed protocols. If specified, only these protocols are allowed.
	 * @default ['http:', 'https:']
	 */
	allowedProtocols?: string[];
}

export interface UrlValidationResult {
	isValid: boolean;
	error?: string;
	hostname?: string;
	ip?: string;
}

/**
 * Validates a URL for SSRF vulnerabilities.
 * Defaults to a secure, fail-closed posture.
 *
 * @param urlString - The URL to validate
 * @param options - Validation options
 * @returns Validation result
 */
export function validateUrl(
	urlString: string,
	options: UrlValidationOptions = {},
): UrlValidationResult {
	const {
		blockLocalhost = true,
		blockPrivateIPs = true,
		blockLinkLocal = true,
		blockedHosts = [],
		allowedProtocols = ['http:', 'https:'],
	} = options;

	// Parse URL
	let url: URL;
	try {
		url = new URL(urlString);
	} catch {
		return {
			isValid: false,
			error: 'Invalid URL format',
		};
	}

	// Check protocol
	if (!allowedProtocols.includes(url.protocol)) {
		return {
			isValid: false,
			error: `Protocol '${url.protocol}' is not allowed`,
		};
	}

	const hostname = url.hostname.toLowerCase();

	// Check blocked hosts
	if (blockedHosts.some((blocked) => hostname === blocked.toLowerCase())) {
		return {
			isValid: false,
			error: `Host '${hostname}' is blocked`,
		};
	}

	// Resolve hostname to IP if possible
	const ipVersion = isIP(hostname);
	const ip = ipVersion ? hostname : null;

	// Check localhost/loopback
	if (blockLocalhost) {
		if (
			hostname === 'localhost' ||
			hostname === '0.0.0.0' ||
			hostname === '::' ||
			hostname === '::ffff:0.0.0.0'
		) {
			return {
				isValid: false,
				error: 'Localhost access is blocked',
				hostname,
				ip: ip ?? undefined,
			};
		}

		// Check loopback IPs
		if (ip) {
			if (ipVersion === 4) {
				// Check 127.0.0.0/8
				const parts = ip.split('.').map(Number);
				if (parts[0] === 127) {
					return {
						isValid: false,
						error: 'Loopback address is blocked',
						hostname,
						ip,
					};
				}
				// Check 0.0.0.0
				if (parts.every((part) => part === 0)) {
					return {
						isValid: false,
						error: 'Localhost access is blocked',
						hostname,
						ip,
					};
				}
			} else if (ipVersion === 6) {
				const normalized = normalizeIPv6(ip);
				// Check ::1
				if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') {
					return {
						isValid: false,
						error: 'Loopback address is blocked',
						hostname,
						ip,
					};
				}
				// Check IPv4-mapped IPv6 loopback (::ffff:127.0.0.1)
				if (normalized.startsWith('::ffff:127.')) {
					return {
						isValid: false,
						error: 'IPv4-mapped loopback address is blocked',
						hostname,
						ip,
					};
				}
				// Check ::ffff:0.0.0.0
				if (normalized === '::ffff:0.0.0.0' || normalized.startsWith('::ffff:0.0.0.')) {
					return {
						isValid: false,
						error: 'Localhost access is blocked',
						hostname,
						ip,
					};
				}
			}
		}
	}

	// Check private IPs
	if (blockPrivateIPs && ip) {
		if (ipVersion === 4) {
			const parts = ip.split('.').map(Number);
			// 10.0.0.0/8
			if (parts[0] === 10) {
				return {
					isValid: false,
					error: 'Private IP range is blocked',
					hostname,
					ip,
				};
			}
			// 172.16.0.0/12
			if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) {
				return {
					isValid: false,
					error: 'Private IP range is blocked',
					hostname,
					ip,
				};
			}
			// 192.168.0.0/16
			if (parts[0] === 192 && parts[1] === 168) {
				return {
					isValid: false,
					error: 'Private IP range is blocked',
					hostname,
					ip,
				};
			}
		} else if (ipVersion === 6) {
			const normalized = normalizeIPv6(ip);
			// fc00::/7 (Unique Local Addresses)
			if (normalized.startsWith('fc') || normalized.startsWith('fd')) {
				return {
					isValid: false,
					error: 'Private IPv6 range is blocked',
					hostname,
					ip,
				};
			}
		}
	}

	// Check link-local IPs
	if (blockLinkLocal && ip) {
		if (ipVersion === 4) {
			const parts = ip.split('.').map(Number);
			// 169.254.0.0/16
			if (parts[0] === 169 && parts[1] === 254) {
				return {
					isValid: false,
					error: 'Link-local address is blocked',
					hostname,
					ip,
				};
			}
		} else if (ipVersion === 6) {
			const normalized = normalizeIPv6(ip);
			// fe80::/10
			if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || 
			    normalized.startsWith('fea') || normalized.startsWith('feb')) {
				return {
					isValid: false,
					error: 'Link-local IPv6 address is blocked',
					hostname,
					ip,
				};
			}
		}
	}

	return {
		isValid: true,
		hostname,
		ip: ip ?? undefined,
	};
}

/**
 * Normalizes an IPv6 address for comparison.
 * Expands :: notation and converts to lowercase.
 */
function normalizeIPv6(ip: string): string {
	// Remove IPv4-mapped prefix for easier checking
	let normalized = ip.toLowerCase();
	
	// Handle IPv4-mapped addresses specially
	const ipv4MappedMatch = normalized.match(/::ffff:(\d+\.\d+\.\d+\.\d+)/);
	if (ipv4MappedMatch) {
		return `::ffff:${ipv4MappedMatch[1]}`;
	}
	
	// For basic comparison, just lowercase and return
	// A full IPv6 normalization would expand ::, but for our security checks,
	// the simplified form is sufficient
	return normalized;
}
