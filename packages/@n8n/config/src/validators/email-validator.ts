/**
 * Email validation using a well-tested approach.
 * 
 * NOTE: Perfect email validation is impossible with regex alone due to RFC 5322 complexity.
 * This validator provides a practical balance between strictness and usability.
 * For critical applications, consider sending a verification email as the final validation.
 */

/**
 * Email validation regex based on a widely-used pattern.
 * This is more permissive than some validators to avoid false negatives,
 * but still catches most malformed emails.
 * 
 * Source: Adapted from HTML5 spec and common best practices
 */
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

export interface EmailValidationOptions {
	/**
	 * Whether to allow multiple @ symbols (not standard)
	 * @default false
	 */
	allowMultipleAt?: boolean;

	/**
	 * Maximum length of the email address
	 * @default 254 (RFC 5321)
	 */
	maxLength?: number;

	/**
	 * Blocked domains (case-insensitive)
	 */
	blockedDomains?: string[];

	/**
	 * Allowed domains (case-insensitive). If specified, only these domains are allowed.
	 */
	allowedDomains?: string[];
}

export interface EmailValidationResult {
	isValid: boolean;
	error?: string;
	email?: string;
	domain?: string;
}

/**
 * Validates an email address.
 * 
 * @param email - The email address to validate
 * @param options - Validation options
 * @returns Validation result
 */
export function validateEmail(
	email: string,
	options: EmailValidationOptions = {},
): EmailValidationResult {
	const {
		allowMultipleAt = false,
		maxLength = 254,
		blockedDomains = [],
		allowedDomains,
	} = options;

	// Check if email is provided and is a string
	if (!email || typeof email !== 'string') {
		return {
			isValid: false,
			error: 'Email is required and must be a string',
		};
	}

	// Trim whitespace
	const trimmedEmail = email.trim();

	// Check length (RFC 5321 limit)
	if (trimmedEmail.length > maxLength) {
		return {
			isValid: false,
			error: `Email must not exceed ${maxLength} characters`,
		};
	}

	// Check for empty after trim
	if (trimmedEmail.length === 0) {
		return {
			isValid: false,
			error: 'Email cannot be empty or only whitespace',
		};
	}

	// Check for multiple @ symbols (unless explicitly allowed)
	const atCount = (trimmedEmail.match(/@/g) || []).length;
	if (!allowMultipleAt && atCount !== 1) {
		return {
			isValid: false,
			error: 'Email must contain exactly one @ symbol',
		};
	}

	// Basic format validation
	if (!EMAIL_REGEX.test(trimmedEmail)) {
		return {
			isValid: false,
			error: 'Email format is invalid',
		};
	}

	// Extract domain
	const parts = trimmedEmail.split('@');
	const domain = parts[parts.length - 1]?.toLowerCase();

	if (!domain) {
		return {
			isValid: false,
			error: 'Email must have a domain',
		};
	}

	// Check for localhost/IP addresses in domain
	if (domain === 'localhost' || /^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
		return {
			isValid: false,
			error: 'Email domain cannot be localhost or an IP address',
		};
	}

	// Check blocked domains
	if (blockedDomains.some((blocked) => domain === blocked.toLowerCase())) {
		return {
			isValid: false,
			error: `Email domain '${domain}' is blocked`,
		};
	}

	// Check allowed domains (if specified)
	if (allowedDomains && allowedDomains.length > 0) {
		const isAllowed = allowedDomains.some((allowed) => domain === allowed.toLowerCase());
		if (!isAllowed) {
			return {
				isValid: false,
				error: `Email domain '${domain}' is not in the allowed list`,
			};
		}
	}

	// Additional format checks
	const localPart = parts[0];
	
	// Check for dots at start or end of local part
	if (localPart?.startsWith('.') || localPart?.endsWith('.')) {
		return {
			isValid: false,
			error: 'Email local part cannot start or end with a dot',
		};
	}

	// Check for consecutive dots
	if (localPart?.includes('..')) {
		return {
			isValid: false,
			error: 'Email local part cannot contain consecutive dots',
		};
	}

	return {
		isValid: true,
		email: trimmedEmail,
		domain,
	};
}

/**
 * Validates multiple email addresses (comma or semicolon separated).
 * 
 * @param emails - String containing one or more email addresses
 * @param separator - Separator character(s) (default: comma or semicolon)
 * @param options - Validation options for each email
 * @returns Object with overall validity and individual results
 */
export function validateMultipleEmails(
	emails: string,
	separator: string | RegExp = /[,;]/,
	options: EmailValidationOptions = {},
): {
	isValid: boolean;
	results: EmailValidationResult[];
	validEmails: string[];
	invalidEmails: string[];
} {
	if (!emails || typeof emails !== 'string') {
		return {
			isValid: false,
			results: [{
				isValid: false,
				error: 'Emails string is required',
			}],
			validEmails: [],
			invalidEmails: [],
		};
	}

	const emailList = emails.split(separator).map(e => e.trim()).filter(e => e.length > 0);
	const results = emailList.map(email => validateEmail(email, options));
	const validEmails = results.filter(r => r.isValid).map(r => r.email!);
	const invalidEmails = emailList.filter((_, i) => !results[i]?.isValid);

	return {
		isValid: results.every(r => r.isValid),
		results,
		validEmails,
		invalidEmails,
	};
}
