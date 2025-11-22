import { validatePassword, validateSecret } from '../password-validator';

describe('Password Validator', () => {
	describe('basic validation', () => {
		it('should reject empty passwords', () => {
			const result = validatePassword('');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('required');
		});

		it('should reject non-string passwords', () => {
			const result = validatePassword(null as any);
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('required');
		});

		it('should reject passwords shorter than minLength', () => {
			const result = validatePassword('short', { minLength: 8 });
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('at least 8 characters');
		});

		it('should reject passwords longer than maxLength', () => {
			const longPassword = 'a'.repeat(200);
			const result = validatePassword(longPassword, { maxLength: 128 });
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('must not exceed');
		});

		it('should accept valid passwords', () => {
			const result = validatePassword('MySecureP@ssw0rd2024');
			expect(result.isValid).toBe(true);
		});
	});

	describe('weak password detection', () => {
		it('should reject common weak passwords', () => {
			const weakPasswords = [
				'password',
				'123456',
				'12345678',
				'qwerty',
				'admin',
				'letmein',
				'password123',
			];

			weakPasswords.forEach(pwd => {
				const result = validatePassword(pwd);
				expect(result.isValid).toBe(false);
				expect(result.error).toContain('too common');
			});
		});

		it('should be case-insensitive for weak password check', () => {
			const result1 = validatePassword('PASSWORD');
			const result2 = validatePassword('PaSsWoRd');
			
			expect(result1.isValid).toBe(false);
			expect(result2.isValid).toBe(false);
		});

		it('should reject all-numeric passwords', () => {
			const result = validatePassword('12345678');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('all numbers');
		});

		it('should reject repeated characters', () => {
			const result1 = validatePassword('aaaaaaaa');
			const result2 = validatePassword('11111111');
			
			expect(result1.isValid).toBe(false);
			expect(result1.error).toContain('repeated character');
			expect(result2.isValid).toBe(false);
		});

		it('should reject sequential patterns', () => {
			const result1 = validatePassword('abc12345');
			const result2 = validatePassword('qwerty123');
			
			expect(result1.isValid).toBe(false);
			expect(result1.error).toContain('sequential');
			expect(result2.isValid).toBe(false);
		});

		it('should allow bypassing weak password check', () => {
			const result = validatePassword('password', { checkWeakPasswords: false });
			expect(result.isValid).toBe(true);
		});
	});

	describe('character requirements', () => {
		const strongBase = 'TestPassword123!';

		it('should enforce uppercase requirement', () => {
			const result1 = validatePassword('testpassword123!', { requireUppercase: true });
			const result2 = validatePassword(strongBase, { requireUppercase: true });
			
			expect(result1.isValid).toBe(false);
			expect(result1.error).toContain('uppercase');
			expect(result2.isValid).toBe(true);
		});

		it('should enforce lowercase requirement', () => {
			const result1 = validatePassword('TESTPASSWORD123!', { requireLowercase: true });
			const result2 = validatePassword(strongBase, { requireLowercase: true });
			
			expect(result1.isValid).toBe(false);
			expect(result1.error).toContain('lowercase');
			expect(result2.isValid).toBe(true);
		});

		it('should enforce digit requirement', () => {
			const result1 = validatePassword('TestPassword!', { requireDigit: true });
			const result2 = validatePassword(strongBase, { requireDigit: true });
			
			expect(result1.isValid).toBe(false);
			expect(result1.error).toContain('digit');
			expect(result2.isValid).toBe(true);
		});

		it('should enforce special character requirement', () => {
			const result1 = validatePassword('TestPassword123', { requireSpecialChar: true });
			const result2 = validatePassword(strongBase, { requireSpecialChar: true });
			
			expect(result1.isValid).toBe(false);
			expect(result1.error).toContain('special character');
			expect(result2.isValid).toBe(true);
		});

		it('should enforce multiple requirements', () => {
			const result = validatePassword(strongBase, {
				requireUppercase: true,
				requireLowercase: true,
				requireDigit: true,
				requireSpecialChar: true,
			});
			
			expect(result.isValid).toBe(true);
		});
	});

	describe('warnings', () => {
		it('should warn about short passwords', () => {
			const result = validatePassword('Short1!a');
			expect(result.isValid).toBe(true);
			expect(result.warnings).toBeDefined();
			expect(result.warnings?.some(w => w.includes('longer password'))).toBe(true);
		});

		it('should warn about lack of character variety', () => {
			const result = validatePassword('alllowercase');
			expect(result.isValid).toBe(true);
			expect(result.warnings).toBeDefined();
			expect(result.warnings?.some(w => w.includes('mix of'))).toBe(true);
		});

		it('should not warn for strong passwords', () => {
			const result = validatePassword('MyVeryStr0ng&SecureP@ssw0rd!2024');
			expect(result.isValid).toBe(true);
			expect(result.warnings).toBeUndefined();
		});
	});

	describe('real-world scenarios', () => {
		it('should accept passphrases', () => {
			const result = validatePassword('correct horse battery staple', { minLength: 20 });
			expect(result.isValid).toBe(true);
		});

		it('should accept passwords with unicode characters', () => {
			const result = validatePassword('Pāsswörd123!こんにちは');
			expect(result.isValid).toBe(true);
		});

		it('should handle edge cases in weak password list', () => {
			const result1 = validatePassword('Password1');
			const result2 = validatePassword('P@ssw0rd');
			
			expect(result1.isValid).toBe(false);
			expect(result2.isValid).toBe(false);
		});
	});
});

describe('Secret Validator', () => {
	describe('basic validation', () => {
		it('should reject empty secrets', () => {
			const result = validateSecret('');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('required');
		});

		it('should reject short secrets', () => {
			const result = validateSecret('short');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('at least 32 characters');
		});

		it('should accept long random secrets', () => {
			// NOTE: This is a test value, not a real API key
			const secret = 'test_key_abc123def456ghi789jklmno012pqr';
			const result = validateSecret(secret);
			expect(result.isValid).toBe(true);
		});

		it('should allow custom minLength', () => {
			const result = validateSecret('abc123def456ghi789', 16);
			expect(result.isValid).toBe(true);
		});
	});

	describe('placeholder detection', () => {
		it('should reject placeholder values', () => {
			const placeholders = [
				'your-secret-here-1234567890abcdef',
				'example_api_key_123456789012345678',
				'sample-token-abcdefghijklmnopqrstuvwxyz',
				'CHANGEME_SECRET_KEY_1234567890ABCDEF',
				'replaceme-api-key-abcdefghijklmnop',
			];

			placeholders.forEach(secret => {
				const result = validateSecret(secret);
				expect(result.isValid).toBe(false);
				expect(result.error).toContain('placeholder');
			});
		});

		it('should be case-insensitive for placeholder check', () => {
			const result = validateSecret('EXAMPLE_API_KEY_1234567890ABCDEFGH');
			expect(result.isValid).toBe(false);
		});
	});

	describe('entropy checks', () => {
		it('should reject repeated characters', () => {
			const result = validateSecret('a'.repeat(40));
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('repeated character');
		});

		it('should reject secrets with low character variety', () => {
			const result = validateSecret('aaabbbcccdddeeefff11112222333344');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('character variety');
		});

		it('should accept secrets with good entropy', () => {
			// NOTE: This is a test value, not a real API key
			const secret = 'test_key_1a2b3c4d5e6f7g8h9i0jklmnopqrs';
			const result = validateSecret(secret);
			expect(result.isValid).toBe(true);
		});
	});

	describe('real-world API keys and tokens', () => {
		it('should accept Stripe-like keys', () => {
			// NOTE: This is a test value, not a real API key
			const secret = 'test_key_51abcdefghijklmnopqrstuvwxyz123456';
			const result = validateSecret(secret);
			expect(result.isValid).toBe(true);
		});

		it('should accept GitHub-like tokens', () => {
			const secret = 'ghp_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcd';
			const result = validateSecret(secret);
			expect(result.isValid).toBe(true);
		});

		it('should accept JWT-like secrets', () => {
			const secret = 'your-256-bit-secret-key-here-random-string-12345';
			// This should fail due to 'your' prefix being a placeholder pattern
			const result = validateSecret(secret);
			expect(result.isValid).toBe(false);
		});

		it('should accept UUID-based secrets', () => {
			const secret = '550e8400-e29b-41d4-a716-446655440000';
			const result = validateSecret(secret, 32);
			expect(result.isValid).toBe(true);
		});
	});
});
