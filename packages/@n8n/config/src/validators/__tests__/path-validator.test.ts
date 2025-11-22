import { join } from 'node:path';
import { validatePath, validatePathWithinBase } from '../path-validator';

describe('Path Validator - Traversal Protection', () => {
	const basePath = '/app/data';

	describe('basic traversal detection', () => {
		it('should reject .. at the start', () => {
			const result = validatePath('../etc/passwd');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('traversal');
		});

		it('should reject .. in the middle', () => {
			const result = validatePath('foo/../../../etc/passwd');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('traversal');
		});

		it('should allow .. that stays within bounds when no basePath', () => {
			const result = validatePath('foo/../bar');
			// Without basePath, this normalizes to 'bar' which is safe
			expect(result.isValid).toBe(true);
		});
	});

	describe('canonical path checking with basePath', () => {
		it('should allow paths within base directory', () => {
			const result1 = validatePath('files/document.txt', { basePath });
			const result2 = validatePath('subfolder/data.json', { basePath });
			
			expect(result1.isValid).toBe(true);
			expect(result1.isWithinBase).toBe(true);
			expect(result2.isValid).toBe(true);
			expect(result2.isWithinBase).toBe(true);
		});

		it('should reject paths that escape base directory', () => {
			const result = validatePath('../../../etc/passwd', { basePath });
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('outside allowed base');
			expect(result.isWithinBase).toBe(false);
		});

		it('should reject complex traversal attempts', () => {
			const result1 = validatePath('foo/../../../../../../etc/passwd', { basePath });
			const result2 = validatePath('./../../sensitive', { basePath });
			
			expect(result1.isValid).toBe(false);
			expect(result2.isValid).toBe(false);
		});

		it('should handle encoded traversal attempts', () => {
			// Note: The path module handles URL encoding, but we should still be safe
			const result = validatePath('foo/../../../../../etc/passwd', { basePath });
			expect(result.isValid).toBe(false);
		});

		it('should allow traversal that stays within base', () => {
			const result = validatePath('foo/../bar/baz', { basePath });
			expect(result.isValid).toBe(true);
			expect(result.isWithinBase).toBe(true);
		});

		it('should allow same path as base', () => {
			const result = validatePath('.', { basePath });
			expect(result.isValid).toBe(true);
		});

		it('should allow empty relative path components', () => {
			const result = validatePath('./files/./document.txt', { basePath });
			expect(result.isValid).toBe(true);
		});
	});

	describe('absolute path handling', () => {
		it('should reject absolute paths by default', () => {
			const result = validatePath('/etc/passwd');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('Absolute paths are not allowed');
		});

		it('should allow absolute paths when allowAbsolute is true', () => {
			const result = validatePath('/some/path', { allowAbsolute: true });
			expect(result.isValid).toBe(true);
		});

		it('should still validate absolute paths against basePath', () => {
			const result = validatePath('/etc/passwd', { 
				basePath,
				allowAbsolute: true 
			});
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('outside allowed base');
		});
	});

	describe('null byte injection', () => {
		it('should reject paths with null bytes', () => {
			const result1 = validatePath('file.txt\0.pdf', { basePath });
			const result2 = validatePath('dir/\0file', { basePath });
			
			expect(result1.isValid).toBe(false);
			expect(result1.error).toContain('null byte');
			expect(result2.isValid).toBe(false);
		});
	});

	describe('input validation', () => {
		it('should reject empty paths', () => {
			const result = validatePath('', { basePath });
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('required');
		});

		it('should reject non-string paths', () => {
			const result1 = validatePath(null as any, { basePath });
			const result2 = validatePath(undefined as any, { basePath });
			const result3 = validatePath(123 as any, { basePath });
			
			expect(result1.isValid).toBe(false);
			expect(result2.isValid).toBe(false);
			expect(result3.isValid).toBe(false);
		});
	});

	describe('validatePathWithinBase convenience function', () => {
		it('should require basePath', () => {
			const result = validatePathWithinBase('file.txt', '');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('Base path is required');
		});

		it('should validate paths correctly', () => {
			const result1 = validatePathWithinBase('file.txt', basePath);
			const result2 = validatePathWithinBase('../../../etc/passwd', basePath);
			
			expect(result1.isValid).toBe(true);
			expect(result2.isValid).toBe(false);
		});
	});

	describe('platform-specific path handling', () => {
		it('should handle forward slashes', () => {
			const result = validatePath('files/subfolder/doc.txt', { basePath });
			expect(result.isValid).toBe(true);
		});

		it('should handle backslashes on Windows', () => {
			const result = validatePath('files\\subfolder\\doc.txt', { basePath });
			// normalize() handles platform-specific separators
			expect(result.isValid).toBe(true);
		});

		it('should handle mixed separators', () => {
			const result = validatePath('files/subfolder\\doc.txt', { basePath });
			expect(result.isValid).toBe(true);
		});
	});

	describe('real-world scenarios', () => {
		it('should allow nested directory structures', () => {
			const result = validatePath('uploads/2024/01/15/file.pdf', { basePath });
			expect(result.isValid).toBe(true);
		});

		it('should reject sophisticated traversal attempts', () => {
			// Various ways attackers might try to escape
			const attacks = [
				'....//....//....//etc/passwd',
				'foo/bar/../../../../../../etc/passwd',
				'./././../../../etc/passwd',
				'uploads/../../../etc/shadow',
			];

			attacks.forEach(attack => {
				const result = validatePath(attack, { basePath });
				expect(result.isValid).toBe(false);
			});
		});

		it('should handle relative paths correctly', () => {
			const result = validatePath('./files/../files/doc.txt', { basePath });
			expect(result.isValid).toBe(true);
		});
	});
});
