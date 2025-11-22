import { validateEmail, validateMultipleEmails } from '../email-validator';

describe('Email Validator', () => {
	describe('basic validation', () => {
		it('should accept valid email addresses', () => {
			const validEmails = [
				'user@example.com',
				'john.doe@example.com',
				'user+tag@example.co.uk',
				'admin@subdomain.example.com',
				'test_user@example-domain.com',
				'123@example.com',
				'a@example.com',
			];

			validEmails.forEach(email => {
				const result = validateEmail(email);
				expect(result.isValid).toBe(true);
			});
		});

		it('should reject invalid email addresses', () => {
			const invalidEmails = [
				'',
				'notanemail',
				'@example.com',
				'user@',
				'user@@example.com',
				'user @example.com',
				'user@example .com',
			];

			invalidEmails.forEach(email => {
				const result = validateEmail(email);
				expect(result.isValid).toBe(false);
			});
		});

		it('should reject empty or whitespace-only emails', () => {
			const result1 = validateEmail('');
			const result2 = validateEmail('   ');
			
			expect(result1.isValid).toBe(false);
			expect(result1.error).toContain('required');
			expect(result2.isValid).toBe(false);
			expect(result2.error).toContain('empty');
		});

		it('should reject non-string emails', () => {
			const result = validateEmail(null as any);
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('required');
		});
	});

	describe('@ symbol validation', () => {
		it('should reject emails without @ symbol', () => {
			const result = validateEmail('userexample.com');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('@ symbol');
		});

		it('should reject emails with multiple @ symbols by default', () => {
			const result = validateEmail('user@@example.com');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('@ symbol');
		});

		it('should allow multiple @ when explicitly enabled', () => {
			const result = validateEmail('user@@example.com', { allowMultipleAt: true });
			// Note: this will still fail format validation, but won't fail on @ count
			expect(result.isValid).toBe(false);
			expect(result.error).not.toContain('@ symbol');
		});
	});

	describe('length validation', () => {
		it('should accept emails up to default max length', () => {
			const longEmail = 'a'.repeat(240) + '@example.com'; // ~252 chars
			const result = validateEmail(longEmail);
			expect(result.isValid).toBe(true);
		});

		it('should reject emails exceeding max length', () => {
			const tooLongEmail = 'a'.repeat(250) + '@example.com'; // >254 chars
			const result = validateEmail(tooLongEmail);
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('must not exceed');
		});

		it('should respect custom max length', () => {
			const result = validateEmail('user@example.com', { maxLength: 10 });
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('must not exceed');
		});
	});

	describe('domain validation', () => {
		it('should extract domain correctly', () => {
			const result = validateEmail('user@example.com');
			expect(result.isValid).toBe(true);
			expect(result.domain).toBe('example.com');
		});

		it('should reject localhost domain', () => {
			const result = validateEmail('user@localhost');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('localhost');
		});

		it('should reject IP address domains', () => {
			const result1 = validateEmail('user@192.168.1.1');
			const result2 = validateEmail('user@127.0.0.1');
			
			expect(result1.isValid).toBe(false);
			expect(result1.error).toContain('IP address');
			expect(result2.isValid).toBe(false);
		});

		it('should accept subdomains', () => {
			const result = validateEmail('user@mail.subdomain.example.com');
			expect(result.isValid).toBe(true);
		});
	});

	describe('blocked domains', () => {
		it('should block specified domains', () => {
			const result = validateEmail('user@spam.com', {
				blockedDomains: ['spam.com', 'malicious.net'],
			});
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('blocked');
		});

		it('should be case-insensitive for blocked domains', () => {
			const result = validateEmail('user@SPAM.COM', {
				blockedDomains: ['spam.com'],
			});
			expect(result.isValid).toBe(false);
		});
	});

	describe('allowed domains', () => {
		it('should only allow specified domains', () => {
			const options = { allowedDomains: ['company.com', 'company.net'] };
			
			const result1 = validateEmail('user@company.com', options);
			const result2 = validateEmail('user@example.com', options);
			
			expect(result1.isValid).toBe(true);
			expect(result2.isValid).toBe(false);
			expect(result2.error).toContain('not in the allowed list');
		});

		it('should be case-insensitive for allowed domains', () => {
			const result = validateEmail('user@COMPANY.COM', {
				allowedDomains: ['company.com'],
			});
			expect(result.isValid).toBe(true);
		});
	});

	describe('local part validation', () => {
		it('should reject dots at start of local part', () => {
			const result = validateEmail('.user@example.com');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('start or end with a dot');
		});

		it('should reject dots at end of local part', () => {
			const result = validateEmail('user.@example.com');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('start or end with a dot');
		});

		it('should reject consecutive dots', () => {
			const result = validateEmail('user..name@example.com');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('consecutive dots');
		});

		it('should accept single dots between characters', () => {
			const result = validateEmail('first.last@example.com');
			expect(result.isValid).toBe(true);
		});

		it('should accept plus signs (common for email aliases)', () => {
			const result = validateEmail('user+tag@example.com');
			expect(result.isValid).toBe(true);
		});
	});

	describe('whitespace handling', () => {
		it('should trim leading and trailing whitespace', () => {
			const result = validateEmail('  user@example.com  ');
			expect(result.isValid).toBe(true);
			expect(result.email).toBe('user@example.com');
		});

		it('should reject emails with internal whitespace', () => {
			const result = validateEmail('user @example.com');
			expect(result.isValid).toBe(false);
		});
	});

	describe('special characters', () => {
		it('should accept RFC-compliant special characters', () => {
			const validEmails = [
				'user+tag@example.com',
				'user_name@example.com',
				'user-name@example.com',
				"user'name@example.com",
				'user!name@example.com',
			];

			validEmails.forEach(email => {
				const result = validateEmail(email);
				expect(result.isValid).toBe(true);
			});
		});
	});

	describe('real-world examples', () => {
		it('should accept common email formats', () => {
			const realEmails = [
				'john.doe@gmail.com',
				'jane_smith@yahoo.co.uk',
				'admin@company-name.com',
				'support+tickets@example.org',
				'user123@mail.example.com',
			];

			realEmails.forEach(email => {
				const result = validateEmail(email);
				expect(result.isValid).toBe(true);
			});
		});
	});
});

describe('Multiple Email Validator', () => {
	describe('basic functionality', () => {
		it('should validate comma-separated emails', () => {
			const result = validateMultipleEmails('user1@example.com, user2@example.com');
			expect(result.isValid).toBe(true);
			expect(result.validEmails).toHaveLength(2);
			expect(result.invalidEmails).toHaveLength(0);
		});

		it('should validate semicolon-separated emails', () => {
			const result = validateMultipleEmails('user1@example.com; user2@example.com');
			expect(result.isValid).toBe(true);
			expect(result.validEmails).toHaveLength(2);
		});

		it('should handle mixed valid and invalid emails', () => {
			const result = validateMultipleEmails('valid@example.com, invalid, good@test.com');
			expect(result.isValid).toBe(false);
			expect(result.validEmails).toHaveLength(2);
			expect(result.invalidEmails).toHaveLength(1);
		});

		it('should trim whitespace from each email', () => {
			const result = validateMultipleEmails('  user1@example.com  ,  user2@example.com  ');
			expect(result.isValid).toBe(true);
			expect(result.validEmails).toEqual(['user1@example.com', 'user2@example.com']);
		});

		it('should handle empty string', () => {
			const result = validateMultipleEmails('');
			expect(result.isValid).toBe(false);
		});

		it('should filter out empty entries', () => {
			const result = validateMultipleEmails('user1@example.com,,,user2@example.com');
			expect(result.validEmails).toHaveLength(2);
		});
	});

	describe('custom separator', () => {
		it('should accept custom separator', () => {
			const result = validateMultipleEmails('user1@example.com|user2@example.com', '|');
			expect(result.isValid).toBe(true);
			expect(result.validEmails).toHaveLength(2);
		});

		it('should accept regex separator', () => {
			const result = validateMultipleEmails('user1@example.com user2@example.com', / /);
			expect(result.isValid).toBe(true);
			expect(result.validEmails).toHaveLength(2);
		});
	});

	describe('validation options', () => {
		it('should apply validation options to all emails', () => {
			const result = validateMultipleEmails(
				'user@company.com, user@external.com',
				',',
				{ allowedDomains: ['company.com'] },
			);
			expect(result.isValid).toBe(false);
			expect(result.validEmails).toHaveLength(1);
			expect(result.invalidEmails).toHaveLength(1);
		});
	});

	describe('individual results', () => {
		it('should provide individual validation results', () => {
			const result = validateMultipleEmails('valid@example.com, invalid');
			expect(result.results).toHaveLength(2);
			expect(result.results[0]?.isValid).toBe(true);
			expect(result.results[1]?.isValid).toBe(false);
		});
	});
});
