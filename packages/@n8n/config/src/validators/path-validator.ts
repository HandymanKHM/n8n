import { resolve, normalize, isAbsolute } from 'node:path';

/**
 * Validates paths to prevent path traversal attacks.
 * Uses canonical path resolution to detect attempts to escape allowed directories.
 */

export interface PathValidationOptions {
	/**
	 * The base directory that paths must resolve within.
	 * If not provided, validation only checks for traversal patterns.
	 */
	basePath?: string;

	/**
	 * Whether to allow absolute paths.
	 * @default false
	 */
	allowAbsolute?: boolean;
}

export interface PathValidationResult {
	isValid: boolean;
	error?: string;
	resolvedPath?: string;
	isWithinBase?: boolean;
}

/**
 * Validates a path for traversal attacks.
 * Defaults to a secure, fail-closed posture.
 *
 * @param userPath - The user-supplied path to validate
 * @param options - Validation options
 * @returns Validation result
 */
export function validatePath(
	userPath: string,
	options: PathValidationOptions = {},
): PathValidationResult {
	const { basePath, allowAbsolute = false } = options;

	// Reject null, undefined, or empty paths
	if (!userPath || typeof userPath !== 'string') {
		return {
			isValid: false,
			error: 'Path is required and must be a string',
		};
	}

	// Reject paths with null bytes (can be used to bypass filters)
	if (userPath.includes('\0')) {
		return {
			isValid: false,
			error: 'Path contains null byte',
		};
	}

	// Check for absolute paths if not allowed
	if (!allowAbsolute && isAbsolute(userPath)) {
		return {
			isValid: false,
			error: 'Absolute paths are not allowed',
		};
	}

	// If basePath is provided, validate that resolved path is within it
	if (basePath) {
		try {
			// Normalize and resolve both paths
			const normalizedBase = normalize(resolve(basePath));
			const resolvedUserPath = normalize(resolve(normalizedBase, userPath));

			// Check if resolved path starts with base path
			// This is the canonical way to detect path traversal
			const isWithinBase = resolvedUserPath.startsWith(normalizedBase + (normalizedBase.endsWith('/') ? '' : '/')) ||
			                     resolvedUserPath === normalizedBase;

			if (!isWithinBase) {
				return {
					isValid: false,
					error: 'Path traversal detected: resolved path is outside allowed base directory',
					resolvedPath: resolvedUserPath,
					isWithinBase: false,
				};
			}

			return {
				isValid: true,
				resolvedPath: resolvedUserPath,
				isWithinBase: true,
			};
		} catch (error) {
			return {
				isValid: false,
				error: `Failed to resolve path: ${error instanceof Error ? error.message : 'Unknown error'}`,
			};
		}
	}

	// If no basePath, just check for obvious traversal patterns
	// This is a fallback check, but canonical checking with basePath is preferred
	const normalized = normalize(userPath);
	
	// Check if normalized path attempts to go up beyond start
	if (normalized.startsWith('..') || normalized.includes('/../')) {
		return {
			isValid: false,
			error: 'Path contains traversal patterns',
			resolvedPath: normalized,
		};
	}

	return {
		isValid: true,
		resolvedPath: normalized,
	};
}

/**
 * Validates that a path is within an allowed directory.
 * This is a convenience function that always requires a basePath.
 *
 * @param userPath - The user-supplied path to validate
 * @param basePath - The base directory that paths must resolve within
 * @returns Validation result
 */
export function validatePathWithinBase(
	userPath: string,
	basePath: string,
): PathValidationResult {
	if (!basePath) {
		return {
			isValid: false,
			error: 'Base path is required',
		};
	}

	return validatePath(userPath, { basePath });
}
