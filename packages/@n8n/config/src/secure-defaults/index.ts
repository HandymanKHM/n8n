/**
 * Secure defaults for security-sensitive configurations.
 * 
 * This module provides secure default configurations for:
 * - Content Security Policy (CSP)
 * - Cookie settings
 * 
 * All defaults are designed to be fail-closed and secure by default,
 * with clear documentation of any limitations or compatibility trade-offs.
 */

export * from './csp-defaults';
export * from './cookie-defaults';
