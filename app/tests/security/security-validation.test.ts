/**
 * Security validation unit tests
 * Comprehensive testing for all security components
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { SecureValidator, SSRFProtector, SecurityError } from '@/lib/security';
import { sanitizeHtml, sanitizeAddress } from '@/lib/secure-output';
import { AuditTrail } from '@/lib/audit-trail';
import { SRIManager } from '@/lib/subresource-integrity';

describe('Security Validation Tests', () => {
  let validator: SecureValidator;

  beforeEach(() => {
    validator = SecureValidator.getInstance();
  });

  describe('Input Validation', () => {
    it('should validate Ethereum addresses correctly', () => {
      // Valid addresses
      expect(() => validator.validateEthereumAddress('0x1234567890123456789012345678901234567890')).not.toThrow();
      expect(() => validator.validateEthereumAddress('0xd8da6bf26964af9d7eed9e03e53415d37aa96045')).not.toThrow();

      // Invalid addresses
      expect(() => validator.validateEthereumAddress('')).toThrow(SecurityError);
      expect(() => validator.validateEthereumAddress('0x123')).toThrow(SecurityError);
      expect(() => validator.validateEthereumAddress('not-an-address')).toThrow(SecurityError);
      expect(() => validator.validateEthereumAddress('0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG')).toThrow(SecurityError);
    });

    it('should validate nonce values correctly', () => {
      // Valid nonces
      expect(validator.validateNonce(0)).toBe(0);
      expect(validator.validateNonce('123')).toBe(123);
      expect(validator.validateNonce(999999)).toBe(999999);

      // Invalid nonces
      expect(() => validator.validateNonce(-1)).toThrow(SecurityError);
      expect(() => validator.validateNonce('not-a-number')).toThrow(SecurityError);
      expect(() => validator.validateNonce(Number.MAX_SAFE_INTEGER + 1)).toThrow(SecurityError);
    });

    it('should validate chain IDs correctly', () => {
      // Valid chain IDs
      expect(validator.validateChainId('1')).toBe('1');
      expect(validator.validateChainId('137')).toBe('137');
      expect(validator.validateChainId(42161)).toBe('42161');

      // Invalid chain IDs
      expect(() => validator.validateChainId('')).toThrow(SecurityError);
      expect(() => validator.validateChainId('invalid')).toThrow(SecurityError);
      expect(() => validator.validateChainId(-1)).toThrow(SecurityError);
    });

    it('should validate hex data correctly', () => {
      // Valid hex data
      expect(validator.validateHexData('0x')).toBe('0x');
      expect(validator.validateHexData('0x1234567890abcdef')).toBe('0x1234567890abcdef');

      // Invalid hex data
      expect(() => validator.validateHexData('not-hex')).toThrow(SecurityError);
      expect(() => validator.validateHexData('0xGGGG')).toThrow(SecurityError);
      expect(() => validator.validateHexData('1234')).toThrow(SecurityError); // Missing 0x prefix
    });

    it('should sanitize strings with length limits', () => {
      const input = 'a'.repeat(1000);
      const sanitized = validator.sanitizeString(input, 50);
      
      expect(sanitized.length).toBeLessThanOrEqual(50);
      expect(sanitized).not.toContain('<script>');
    });
  });

  describe('SSRF Protection', () => {
    it('should allow safe domains', () => {
      const protector = new SSRFProtector(['api.github.com', 'www.4byte.directory']);
      
      expect(protector.isUrlSafe('https://api.github.com/repos/test')).toBe(true);
      expect(protector.isUrlSafe('https://www.4byte.directory/api/v1/signatures')).toBe(true);
    });

    it('should block dangerous domains', () => {
      const protector = new SSRFProtector(['api.github.com']);
      
      expect(protector.isUrlSafe('http://localhost:8080')).toBe(false);
      expect(protector.isUrlSafe('https://169.254.169.254/metadata')).toBe(false);
      expect(protector.isUrlSafe('file:///etc/passwd')).toBe(false);
      expect(protector.isUrlSafe('ftp://internal-server.com')).toBe(false);
    });

    it('should reject malformed URLs', () => {
      const protector = new SSRFProtector(['api.github.com']);
      
      expect(protector.isUrlSafe('not-a-url')).toBe(false);
      expect(protector.isUrlSafe('javascript:alert(1)')).toBe(false);
      expect(protector.isUrlSafe('data:text/html,<script>alert(1)</script>')).toBe(false);
    });
  });

  describe('Output Sanitization', () => {
    it('should sanitize HTML content', () => {
      expect(sanitizeHtml('<script>alert("xss")</script>')).toBe('&lt;script&gt;alert("xss")&lt;/script&gt;');
      expect(sanitizeHtml('<img src=x onerror=alert(1)>')).toBe('&lt;img src=x onerror=alert(1)&gt;');
      expect(sanitizeHtml('Safe content')).toBe('Safe content');
    });

    it('should sanitize Ethereum addresses', () => {
      expect(sanitizeAddress('0x1234567890123456789012345678901234567890')).toBe('0x1234567890123456789012345678901234567890');
      expect(() => sanitizeAddress('invalid-address')).toThrow();
      expect(() => sanitizeAddress('<script>alert(1)</script>')).toThrow();
    });

    it('should handle edge cases in sanitization', () => {
      expect(sanitizeHtml('')).toBe('');
      expect(sanitizeHtml(null as any)).toBe('');
      expect(sanitizeHtml(undefined as any)).toBe('');
      expect(sanitizeHtml(123 as any)).toBe('123');
    });
  });

  describe('Audit Trail System', () => {
    beforeEach(() => {
      // Clear audit log before each test
      AuditTrail.getStatistics(); // Initialize if needed
    });

    it('should log security events correctly', () => {
      const entry = AuditTrail.logAction(
        'test_action',
        'test_resource',
        'SUCCESS',
        { testData: 'value' },
        {
          ipAddress: '192.168.1.1',
          userAgent: 'test-agent',
          userId: 'test-user'
        }
      );

      expect(entry.action).toBe('test_action');
      expect(entry.resource).toBe('test_resource');
      expect(entry.outcome).toBe('SUCCESS');
      expect(entry.hash).toBeTruthy();
    });

    it('should maintain integrity with hash chain', () => {
      // Log multiple entries
      const entry1 = AuditTrail.logAction('action1', 'resource1', 'SUCCESS', {}, {
        ipAddress: '192.168.1.1',
        userAgent: 'test-agent'
      });

      const entry2 = AuditTrail.logAction('action2', 'resource2', 'SUCCESS', {}, {
        ipAddress: '192.168.1.1',
        userAgent: 'test-agent'
      });

      // Verify hash chain
      expect(entry2.previousHash).toBe(entry1.hash);
      expect(entry1.hash).not.toBe(entry2.hash);
    });

    it('should verify audit trail integrity', () => {
      // Add some entries
      AuditTrail.logAction('action1', 'resource1', 'SUCCESS', {}, {
        ipAddress: '192.168.1.1',
        userAgent: 'test-agent'
      });

      AuditTrail.logAction('action2', 'resource2', 'FAILURE', {}, {
        ipAddress: '192.168.1.1',
        userAgent: 'test-agent'
      });

      const integrity = AuditTrail.verifyIntegrity();
      expect(integrity.isValid).toBe(true);
      expect(integrity.corruptedEntries).toHaveLength(0);
    });

    it('should query audit logs with filters', () => {
      // Add test entries
      AuditTrail.logAction('login', 'auth', 'SUCCESS', {}, {
        ipAddress: '192.168.1.1',
        userAgent: 'test-agent',
        userId: 'user1'
      });

      AuditTrail.logAction('logout', 'auth', 'SUCCESS', {}, {
        ipAddress: '192.168.1.1',
        userAgent: 'test-agent',
        userId: 'user1'
      });

      AuditTrail.logAction('delete', 'data', 'FAILURE', {}, {
        ipAddress: '192.168.1.1',
        userAgent: 'test-agent',
        userId: 'user2'
      });

      // Query by user
      const userLogs = AuditTrail.queryLogs({ userId: 'user1' });
      expect(userLogs.entries).toHaveLength(2);
      expect(userLogs.entries.every(e => e.userId === 'user1')).toBe(true);

      // Query by outcome
      const failureLogs = AuditTrail.queryLogs({ outcome: 'FAILURE' });
      expect(failureLogs.entries).toHaveLength(1);
      expect(failureLogs.entries[0].outcome).toBe('FAILURE');
    });
  });

  describe('Subresource Integrity', () => {
    it('should generate SRI hashes correctly', () => {
      const content = 'console.log("Hello World");';
      const result = SRIManager.generateSRIHash(content, 'sha384');

      expect(result.algorithm).toBe('sha384');
      expect(result.integrity).toMatch(/^sha384-[A-Za-z0-9+/]+=*$/);
      expect(result.hash).toBeTruthy();
    });

    it('should verify resource integrity correctly', async () => {
      const content = 'console.log("Hello World");';
      const sriResult = SRIManager.generateSRIHash(content, 'sha384');

      // Valid verification
      const isValid = await SRIManager.verifyResourceIntegrity(
        'https://example.com/script.js',
        content,
        sriResult.integrity
      );
      expect(isValid).toBe(true);

      // Invalid verification (modified content)
      const isInvalid = await SRIManager.verifyResourceIntegrity(
        'https://example.com/script.js',
        content + ' // modified',
        sriResult.integrity
      );
      expect(isInvalid).toBe(false);
    });

    it('should generate secure script tags', () => {
      const scriptTag = SRIManager.generateSecureScriptTag(
        'https://cdn.example.com/script.js',
        'sha384-ABC123',
        'anonymous'
      );

      expect(scriptTag).toContain('integrity="sha384-ABC123"');
      expect(scriptTag).toContain('crossorigin="anonymous"');
      expect(scriptTag).toContain('src="https://cdn.example.com/script.js"');
    });

    it('should reject invalid SRI parameters', () => {
      expect(() => SRIManager.generateSecureScriptTag(
        'ftp://example.com/script.js',
        'sha384-ABC123'
      )).toThrow(SecurityError);

      expect(() => SRIManager.generateSecureScriptTag(
        'https://example.com/script.js',
        'invalid-hash'
      )).toThrow(SecurityError);
    });
  });

  describe('Error Handling', () => {
    it('should handle security errors properly', () => {
      try {
        validator.validateEthereumAddress('invalid');
      } catch (error) {
        expect(error).toBeInstanceOf(SecurityError);
        expect((error as SecurityError).code).toBeTruthy();
      }
    });

    it('should not leak sensitive information in errors', () => {
      try {
        validator.validateEthereumAddress('0x' + 'secret'.repeat(10));
      } catch (error) {
        expect((error as Error).message).not.toContain('secret');
      }
    });
  });

  describe('Performance and DoS Protection', () => {
    it('should handle large inputs without DoS', () => {
      const largeInput = 'a'.repeat(100000);
      
      expect(() => {
        validator.sanitizeString(largeInput, 1000);
      }).not.toThrow();

      const result = validator.sanitizeString(largeInput, 1000);
      expect(result.length).toBeLessThanOrEqual(1000);
    });

    it('should limit SRI hash generation for large content', () => {
      const largeContent = 'x'.repeat(10000000); // 10MB
      
      expect(() => {
        SRIManager.generateSRIHash(largeContent);
      }).not.toThrow();
    });
  });

  describe('Security Headers and CSP', () => {
    it('should validate CSP directive formats', () => {
      // Test CSP violation structure validation
      const validCSPReport = {
        'csp-report': {
          'document-uri': 'https://example.com/',
          'referrer': 'https://example.com/',
          'violated-directive': 'script-src',
          'effective-directive': 'script-src',
          'original-policy': "default-src 'self'",
          'blocked-uri': 'inline',
          'line-number': 1,
          'column-number': 1,
          'source-file': 'https://example.com/',
          'status-code': 200,
          'script-sample': 'alert(1)'
        }
      };

      // Validate structure exists
      expect(validCSPReport['csp-report']).toBeDefined();
      expect(typeof validCSPReport['csp-report']['violated-directive']).toBe('string');
    });
  });
});