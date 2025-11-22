import { validateUrl } from '../url-validator';

describe('URL Validator - SSRF Protection', () => {
	describe('localhost blocking', () => {
		it('should block localhost hostname', () => {
			const result = validateUrl('http://localhost:8080/api');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('Localhost');
		});

		it('should block 127.0.0.1', () => {
			const result = validateUrl('http://127.0.0.1/');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('Loopback');
		});

		it('should block 127.x.x.x range', () => {
			const result1 = validateUrl('http://127.0.0.1/');
			const result2 = validateUrl('http://127.1.1.1/');
			const result3 = validateUrl('http://127.255.255.255/');
			
			expect(result1.isValid).toBe(false);
			expect(result2.isValid).toBe(false);
			expect(result3.isValid).toBe(false);
		});

		it('should block 0.0.0.0', () => {
			const result = validateUrl('http://0.0.0.0/');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('Localhost');
		});

		it('should block IPv6 loopback ::1', () => {
			const result = validateUrl('http://[::1]/');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('Loopback');
		});

		it('should block IPv4-mapped IPv6 loopback ::ffff:127.0.0.1', () => {
			const result = validateUrl('http://[::ffff:127.0.0.1]/');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('loopback');
		});

		it('should block ::ffff:0.0.0.0', () => {
			const result = validateUrl('http://[::ffff:0.0.0.0]/');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('Localhost');
		});

		it('should allow localhost when blockLocalhost is false', () => {
			const result = validateUrl('http://localhost/', { blockLocalhost: false });
			expect(result.isValid).toBe(true);
		});
	});

	describe('private IP blocking', () => {
		it('should block 10.0.0.0/8 range', () => {
			const result1 = validateUrl('http://10.0.0.1/');
			const result2 = validateUrl('http://10.255.255.255/');
			
			expect(result1.isValid).toBe(false);
			expect(result1.error).toContain('Private IP');
			expect(result2.isValid).toBe(false);
		});

		it('should block 172.16.0.0/12 range', () => {
			const result1 = validateUrl('http://172.16.0.1/');
			const result2 = validateUrl('http://172.31.255.255/');
			
			expect(result1.isValid).toBe(false);
			expect(result1.error).toContain('Private IP');
			expect(result2.isValid).toBe(false);
		});

		it('should NOT block 172.15.x.x or 172.32.x.x (outside range)', () => {
			const result1 = validateUrl('http://172.15.0.1/', { blockPrivateIPs: true });
			const result2 = validateUrl('http://172.32.0.1/', { blockPrivateIPs: true });
			
			expect(result1.isValid).toBe(true);
			expect(result2.isValid).toBe(true);
		});

		it('should block 192.168.0.0/16 range', () => {
			const result1 = validateUrl('http://192.168.0.1/');
			const result2 = validateUrl('http://192.168.255.255/');
			
			expect(result1.isValid).toBe(false);
			expect(result1.error).toContain('Private IP');
			expect(result2.isValid).toBe(false);
		});

		it('should block IPv6 private range fc00::/7', () => {
			const result1 = validateUrl('http://[fc00::1]/');
			const result2 = validateUrl('http://[fd00::1]/');
			
			expect(result1.isValid).toBe(false);
			expect(result1.error).toContain('Private IPv6');
			expect(result2.isValid).toBe(false);
		});

		it('should allow private IPs when blockPrivateIPs is false', () => {
			const result = validateUrl('http://192.168.1.1/', { blockPrivateIPs: false });
			expect(result.isValid).toBe(true);
		});
	});

	describe('link-local blocking', () => {
		it('should block 169.254.0.0/16 range', () => {
			const result1 = validateUrl('http://169.254.0.1/');
			const result2 = validateUrl('http://169.254.255.255/');
			
			expect(result1.isValid).toBe(false);
			expect(result1.error).toContain('Link-local');
			expect(result2.isValid).toBe(false);
		});

		it('should block IPv6 link-local fe80::/10', () => {
			const result = validateUrl('http://[fe80::1]/');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('Link-local');
		});

		it('should allow link-local when blockLinkLocal is false', () => {
			const result = validateUrl('http://169.254.1.1/', { blockLinkLocal: false });
			expect(result.isValid).toBe(true);
		});
	});

	describe('protocol validation', () => {
		it('should allow http and https by default', () => {
			const result1 = validateUrl('http://example.com/');
			const result2 = validateUrl('https://example.com/');
			
			expect(result1.isValid).toBe(true);
			expect(result2.isValid).toBe(true);
		});

		it('should block other protocols by default', () => {
			const result1 = validateUrl('file:///etc/passwd');
			const result2 = validateUrl('ftp://example.com/');
			const result3 = validateUrl('javascript:alert(1)');
			
			expect(result1.isValid).toBe(false);
			expect(result1.error).toContain('Protocol');
			expect(result2.isValid).toBe(false);
			expect(result3.isValid).toBe(false);
		});

		it('should respect custom allowed protocols', () => {
			const result = validateUrl('ftp://example.com/', { 
				allowedProtocols: ['ftp:'] 
			});
			expect(result.isValid).toBe(true);
		});
	});

	describe('custom blocked hosts', () => {
		it('should block hosts in blockedHosts list', () => {
			const result = validateUrl('http://evil.com/', { 
				blockedHosts: ['evil.com', 'malicious.net'] 
			});
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('blocked');
		});

		it('should be case-insensitive', () => {
			const result = validateUrl('http://EVIL.COM/', { 
				blockedHosts: ['evil.com'] 
			});
			expect(result.isValid).toBe(false);
		});
	});

	describe('valid external URLs', () => {
		it('should allow valid external domains', () => {
			const result1 = validateUrl('http://example.com/');
			const result2 = validateUrl('https://api.github.com/repos');
			const result3 = validateUrl('http://subdomain.example.org:8080/path');
			
			expect(result1.isValid).toBe(true);
			expect(result2.isValid).toBe(true);
			expect(result3.isValid).toBe(true);
		});

		it('should allow public IP addresses', () => {
			const result1 = validateUrl('http://8.8.8.8/');
			const result2 = validateUrl('http://1.1.1.1/');
			
			expect(result1.isValid).toBe(true);
			expect(result2.isValid).toBe(true);
		});
	});

	describe('invalid URLs', () => {
		it('should reject malformed URLs', () => {
			const result1 = validateUrl('not a url');
			const result2 = validateUrl('http://');
			const result3 = validateUrl('');
			
			expect(result1.isValid).toBe(false);
			expect(result1.error).toContain('Invalid URL');
			expect(result2.isValid).toBe(false);
			expect(result3.isValid).toBe(false);
		});
	});

	describe('edge cases', () => {
		it('should handle URLs with authentication', () => {
			const result = validateUrl('http://user:pass@127.0.0.1/');
			expect(result.isValid).toBe(false);
			expect(result.error).toContain('Loopback');
		});

		it('should handle URLs with query strings and fragments', () => {
			const result = validateUrl('http://127.0.0.1/?param=value#fragment');
			expect(result.isValid).toBe(false);
		});

		it('should handle URLs with non-standard ports', () => {
			const result = validateUrl('http://example.com:9000/');
			expect(result.isValid).toBe(true);
		});
	});
});
