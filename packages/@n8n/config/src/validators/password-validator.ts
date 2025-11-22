/**
 * Validates password and secret strength.
 * Uses a curated list of obviously weak values.
 * 
 * NOTE: This is a basic validator for catching obviously weak passwords.
 * For production systems, consider additional measures:
 * - Checking against breach databases (Have I Been Pwned API)
 * - Entropy calculation
 * - Dictionary checks
 * - Pattern detection (keyboard walks, repeated characters, etc.)
 */

/**
 * Common weak passwords and secrets that should always be rejected.
 * This list focuses on exact matches of the most common weak values.
 */
const WEAK_PASSWORDS = new Set([
	// Most common passwords
	'password',
	'password123',
	'123456',
	'12345678',
	'123456789',
	'1234567890',
	'qwerty',
	'abc123',
	'password1',
	'admin',
	'admin123',
	'letmein',
	'welcome',
	'monkey',
	'dragon',
	'master',
	'sunshine',
	'princess',
	'football',
	'baseball',
	'starwars',
	'shadow',
	'michael',
	'jennifer',
	'111111',
	'000000',
	'654321',
	'superman',
	'batman',
	'trustno1',
	'password!',
	'Password1',
	'Password123',
	'P@ssw0rd',
	'P@ssword',
	'P@ssword1',
	'iloveyou',
	'welcome1',
	'admin1',
	'root',
	'toor',
	'pass',
	'test',
	'test123',
	'guest',
	'changeme',
	'default',
	'secret',
	'secret123',
]);

/**
 * Common weak secret patterns (case-insensitive substrings)
 */
const WEAK_SECRET_PATTERNS = [
	'example',
	'sample',
	'changeme',
	'replaceme',
	'your-secret-here',
	'your-key-here',
	'placeholder',
	'dummy',
	'temp',
	'temporary',
];

export interface PasswordValidationOptions {
	/**
	 * Minimum password length
	 * @default 8
	 */
	minLength?: number;

	/**
	 * Maximum password length (to prevent DoS)
	 * @default 128
	 */
	maxLength?: number;

	/**
	 * Whether to check for common weak passwords
	 * @default true
	 */
	checkWeakPasswords?: boolean;

	/**
	 * Whether to require at least one uppercase letter
	 * @default false
	 */
	requireUppercase?: boolean;

	/**
	 * Whether to require at least one lowercase letter
	 * @default false
	 */
	requireLowercase?: boolean;

	/**
	 * Whether to require at least one digit
	 * @default false
	 */
	requireDigit?: boolean;

	/**
	 * Whether to require at least one special character
	 * @default false
	 */
	requireSpecialChar?: boolean;
}

export interface PasswordValidationResult {
	isValid: boolean;
	error?: string;
	warnings?: string[];
}

/**
 * Validates password strength.
 * Defaults to checking length and weak password list.
 *
 * @param password - The password to validate
 * @param options - Validation options
 * @returns Validation result
 */
export function validatePassword(
	password: string,
	options: PasswordValidationOptions = {},
): PasswordValidationResult {
	const {
		minLength = 8,
		maxLength = 128,
		checkWeakPasswords = true,
		requireUppercase = false,
		requireLowercase = false,
		requireDigit = false,
		requireSpecialChar = false,
	} = options;

	const warnings: string[] = [];

	// Check if password is provided
	if (!password || typeof password !== 'string') {
		return {
			isValid: false,
			error: 'Password is required and must be a string',
		};
	}

	// Check minimum length
	if (password.length < minLength) {
		return {
			isValid: false,
			error: `Password must be at least ${minLength} characters long`,
		};
	}

	// Check maximum length (prevent DoS)
	if (password.length > maxLength) {
		return {
			isValid: false,
			error: `Password must not exceed ${maxLength} characters`,
		};
	}

	// Check for weak passwords (exact match, case-insensitive)
	if (checkWeakPasswords) {
		const lowerPassword = password.toLowerCase();
		if (WEAK_PASSWORDS.has(lowerPassword)) {
			return {
				isValid: false,
				error: 'Password is too common and easily guessable',
			};
		}

		// Check for numeric-only passwords
		if (/^\d+$/.test(password)) {
			return {
				isValid: false,
				error: 'Password cannot be all numbers',
			};
		}

		// Check for very simple patterns
		if (/^(.)\1+$/.test(password)) {
			return {
				isValid: false,
				error: 'Password cannot be a repeated character',
			};
		}

		// Check for sequential patterns
		if (isSequentialPattern(password)) {
			return {
				isValid: false,
				error: 'Password contains sequential patterns',
			};
		}
	}

	// Check character requirements
	if (requireUppercase && !/[A-Z]/.test(password)) {
		return {
			isValid: false,
			error: 'Password must contain at least one uppercase letter',
		};
	}

	if (requireLowercase && !/[a-z]/.test(password)) {
		return {
			isValid: false,
			error: 'Password must contain at least one lowercase letter',
		};
	}

	if (requireDigit && !/\d/.test(password)) {
		return {
			isValid: false,
			error: 'Password must contain at least one digit',
		};
	}

	if (requireSpecialChar && !/[^A-Za-z0-9]/.test(password)) {
		return {
			isValid: false,
			error: 'Password must contain at least one special character',
		};
	}

	// Add warnings for weak but acceptable passwords
	if (password.length < 12) {
		warnings.push('Consider using a longer password (12+ characters) for better security');
	}

	const hasVariety = [
		/[A-Z]/.test(password),
		/[a-z]/.test(password),
		/\d/.test(password),
		/[^A-Za-z0-9]/.test(password),
	].filter(Boolean).length;

	if (hasVariety < 3) {
		warnings.push('Consider using a mix of uppercase, lowercase, numbers, and special characters');
	}

	return {
		isValid: true,
		warnings: warnings.length > 0 ? warnings : undefined,
	};
}

/**
 * Validates secret/token strength.
 * Secrets have slightly different requirements than user passwords.
 *
 * @param secret - The secret to validate
 * @param minLength - Minimum length (default: 32 for API keys/tokens)
 * @returns Validation result
 */
export function validateSecret(
	secret: string,
	minLength: number = 32,
): PasswordValidationResult {
	if (!secret || typeof secret !== 'string') {
		return {
			isValid: false,
			error: 'Secret is required and must be a string',
		};
	}

	// Check minimum length
	if (secret.length < minLength) {
		return {
			isValid: false,
			error: `Secret must be at least ${minLength} characters long`,
		};
	}

	// Check for weak secret patterns (case-insensitive)
	const lowerSecret = secret.toLowerCase();
	for (const pattern of WEAK_SECRET_PATTERNS) {
		if (lowerSecret.includes(pattern)) {
			return {
				isValid: false,
				error: `Secret appears to be a placeholder or example value`,
			};
		}
	}

	// Check for overly simple secrets
	if (/^(.)\1+$/.test(secret)) {
		return {
			isValid: false,
			error: 'Secret cannot be a repeated character',
		};
	}

	// Secrets should have reasonable entropy
	const uniqueChars = new Set(secret).size;
	if (uniqueChars < 10) {
		return {
			isValid: false,
			error: 'Secret lacks sufficient character variety',
		};
	}

	return {
		isValid: true,
	};
}

/**
 * Checks if a string contains sequential patterns like '123', 'abc', etc.
 */
function isSequentialPattern(str: string): boolean {
	const lower = str.toLowerCase();
	
	// Check for sequential numbers
	if (lower.includes('0123') || lower.includes('1234') || lower.includes('2345') ||
	    lower.includes('3456') || lower.includes('4567') || lower.includes('5678') ||
	    lower.includes('6789')) {
		return true;
	}

	// Check for sequential letters
	if (lower.includes('abcd') || lower.includes('bcde') || lower.includes('cdef') ||
	    lower.includes('defg') || lower.includes('efgh') || lower.includes('fghi')) {
		return true;
	}

	// Check for keyboard patterns
	if (lower.includes('qwerty') || lower.includes('asdfgh') || lower.includes('zxcvbn')) {
		return true;
	}

	return false;
}
