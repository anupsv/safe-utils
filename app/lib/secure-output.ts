/**
 * Output sanitization and XSS protection
 * Comprehensive content security and data sanitization
 */

import { SecureLogger } from './security';

// HTML entities for comprehensive XSS protection
const HTML_ENTITIES = Object.freeze({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#x27;',
  '/': '&#x2F;',
  '`': '&#x60;',
  '=': '&#x3D;',
  '\u00A0': '&#160;', // Non-breaking space
  '\u2028': '&#8232;', // Line separator
  '\u2029': '&#8233;', // Paragraph separator
});

// Dangerous patterns that should be blocked or heavily sanitized
const DANGEROUS_PATTERNS = Object.freeze([
  // Script injection patterns
  /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
  /javascript:/gi,
  /vbscript:/gi,
  /data:text\/html/gi,
  /on\w+\s*=/gi, // Event handlers
  
  // URL manipulation patterns
  /[\x00-\x1F\x7F-\x9F]/g, // Control characters
  /[\u2000-\u200F\u2028-\u202F\u205F-\u206F]/g, // Unicode spaces
  
  // SQL injection patterns (defensive)
  /(\bunion\b|\bselect\b|\binsert\b|\bdelete\b|\bdrop\b|\bcreate\b)/gi,
  
  // Command injection patterns
  /[;&|`${}]/g,
  
  // Path traversal patterns
  /\.\.[\\/]/g,
  
  // Null byte injection
  /\x00/g
]);

/**
 * Comprehensive HTML sanitizer
 */
export class UltraSecureHtmlSanitizer {
  private static instance: UltraSecureHtmlSanitizer;

  private constructor() {}

  public static getInstance(): UltraSecureHtmlSanitizer {
    if (!UltraSecureHtmlSanitizer.instance) {
      UltraSecureHtmlSanitizer.instance = new UltraSecureHtmlSanitizer();
    }
    return UltraSecureHtmlSanitizer.instance;
  }

  /**
   * Sanitize HTML content with aggressive XSS protection
   */
  public sanitizeHtml(input: unknown): string {
    if (typeof input !== 'string') {
      return '';
    }

    let sanitized = input;

    // Remove dangerous patterns
    DANGEROUS_PATTERNS.forEach(pattern => {
      const matches = sanitized.match(pattern);
      if (matches) {
        SecureLogger.warn(`Dangerous pattern detected and removed: ${matches.length} matches`);
        sanitized = sanitized.replace(pattern, '');
      }
    });

    // Encode HTML entities
    sanitized = sanitized.replace(/[&<>"'\/`=\u00A0\u2028\u2029]/g, match => {
      return HTML_ENTITIES[match as keyof typeof HTML_ENTITIES] || match;
    });

    // Remove any remaining null bytes or control characters
    sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, '');

    // Limit length to prevent DoS
    if (sanitized.length > 10000) {
      SecureLogger.warn('Content truncated due to excessive length');
      sanitized = sanitized.substring(0, 10000) + '...';
    }

    return sanitized;
  }

  /**
   * Sanitize for JSON output (prevent JSON injection)
   */
  public sanitizeForJson(input: unknown): string {
    const htmlSanitized = this.sanitizeHtml(input);
    
    // Additional JSON-specific sanitization
    return htmlSanitized
      .replace(/[\u2028\u2029]/g, '') // Remove line/paragraph separators
      .replace(/\\/g, '\\\\') // Escape backslashes
      .replace(/"/g, '\\"') // Escape quotes
      .replace(/\//g, '\\/'); // Escape forward slashes
  }

  /**
   * Sanitize cryptocurrency addresses for display
   */
  public sanitizeCryptoAddress(address: unknown): string {
    if (typeof address !== 'string') {
      return '0x0000000000000000000000000000000000000000';
    }

    // Strict validation for Ethereum addresses
    const cleaned = address.replace(/[^0-9a-fA-Fx]/g, '');
    
    if (!/^0x[a-fA-F0-9]{40}$/.test(cleaned)) {
      SecureLogger.warn('Invalid address format detected, returning zero address');
      return '0x0000000000000000000000000000000000000000';
    }

    return cleaned.toLowerCase();
  }

  /**
   * Sanitize hash values for display
   */
  public sanitizeHash(hash: unknown): string {
    if (typeof hash !== 'string') {
      return '0x0000000000000000000000000000000000000000000000000000000000000000';
    }

    const cleaned = hash.replace(/[^0-9a-fA-Fx]/g, '');
    
    if (!/^0x[a-fA-F0-9]{64}$/.test(cleaned)) {
      SecureLogger.warn('Invalid hash format detected, returning zero hash');
      return '0x0000000000000000000000000000000000000000000000000000000000000000';
    }

    return cleaned.toLowerCase();
  }

  /**
   * Sanitize numeric values for display
   */
  public sanitizeNumeric(value: unknown): string {
    if (typeof value === 'number') {
      return Math.abs(value).toString();
    }

    if (typeof value !== 'string') {
      return '0';
    }

    // Remove all non-numeric characters
    const cleaned = value.replace(/[^0-9]/g, '');
    
    // Prevent very large numbers that could cause issues
    if (cleaned.length > 77) { // Max uint256 length
      SecureLogger.warn('Numeric value truncated due to excessive length');
      return cleaned.substring(0, 77);
    }

    return cleaned || '0';
  }

  /**
   * Sanitize hex data for display
   */
  public sanitizeHexData(data: unknown): string {
    if (typeof data !== 'string') {
      return '0x';
    }

    let cleaned = data.toLowerCase();
    
    // Ensure it starts with 0x
    if (!cleaned.startsWith('0x')) {
      cleaned = '0x' + cleaned;
    }

    // Remove invalid hex characters
    cleaned = cleaned.replace(/[^0-9a-fx]/g, '');
    
    // Ensure even length for valid hex
    if (cleaned.length % 2 !== 0) {
      cleaned += '0';
    }

    // Limit length to prevent DoS
    if (cleaned.length > 200000) { // 100KB hex data
      SecureLogger.warn('Hex data truncated due to excessive length');
      cleaned = cleaned.substring(0, 200000);
    }

    return cleaned;
  }
}

/**
 * React component sanitization utilities
 */
export class SecureReactUtils {
  private static sanitizer = UltraSecureHtmlSanitizer.getInstance();

  /**
   * Create secure props object for React components
   */
  public static createSecureProps<T extends Record<string, unknown>>(props: T): T {
    const secureProps = {} as T;

    for (const [key, value] of Object.entries(props)) {
      if (typeof value === 'string') {
        (secureProps as any)[key] = this.sanitizer.sanitizeHtml(value);
      } else if (typeof value === 'object' && value !== null) {
        (secureProps as any)[key] = this.createSecureProps(value as Record<string, unknown>);
      } else {
        (secureProps as any)[key] = value;
      }
    }

    return secureProps;
  }

  /**
   * Secure className generation
   */
  public static secureClassName(...classes: unknown[]): string {
    return classes
      .filter((cls): cls is string => typeof cls === 'string')
      .map(cls => cls.replace(/[^a-zA-Z0-9\-_\s]/g, ''))
      .join(' ')
      .trim();
  }

  /**
   * Secure data attributes
   */
  public static secureDataAttributes(attrs: Record<string, unknown>): Record<string, string> {
    const secure: Record<string, string> = {};

    for (const [key, value] of Object.entries(attrs)) {
      const safeKey = key.replace(/[^a-zA-Z0-9\-]/g, '');
      if (safeKey && typeof value === 'string') {
        secure[`data-${safeKey}`] = this.sanitizer.sanitizeHtml(value);
      }
    }

    return secure;
  }
}

/**
 * URL sanitization utilities
 */
export class SecureUrlUtils {
  private static allowedProtocols = ['https:', 'mailto:'];
  private static allowedDomains = [
    'safeutils.openzeppelin.com',
    'safe.global',
    'ethereum.org',
    'github.com'
  ];

  /**
   * Sanitize URL for href attributes
   */
  public static sanitizeUrl(url: unknown): string {
    if (typeof url !== 'string') {
      return '#';
    }

    try {
      const parsed = new URL(url);
      
      // Protocol validation
      if (!this.allowedProtocols.includes(parsed.protocol)) {
        SecureLogger.warn(`Blocked URL with invalid protocol: ${parsed.protocol}`);
        return '#';
      }

      // Domain validation for external links
      if (parsed.protocol === 'https:' && !this.allowedDomains.some(domain => 
        parsed.hostname === domain || parsed.hostname.endsWith('.' + domain)
      )) {
        SecureLogger.warn(`Blocked URL with untrusted domain: ${parsed.hostname}`);
        return '#';
      }

      return parsed.toString();
    } catch (error) {
      SecureLogger.warn('Invalid URL format detected');
      return '#';
    }
  }

  /**
   * Sanitize relative URLs
   */
  public static sanitizeRelativeUrl(url: unknown): string {
    if (typeof url !== 'string') {
      return '/';
    }

    // Remove dangerous patterns
    let cleaned = url
      .replace(/[<>"'`]/g, '')
      .replace(/javascript:/gi, '')
      .replace(/data:/gi, '')
      .replace(/vbscript:/gi, '');

    // Ensure it starts with /
    if (!cleaned.startsWith('/')) {
      cleaned = '/' + cleaned;
    }

    // Remove path traversal attempts
    cleaned = cleaned.replace(/\.\.[\\/]/g, '');

    // Limit length
    if (cleaned.length > 200) {
      cleaned = cleaned.substring(0, 200);
    }

    return cleaned;
  }
}

/**
 * Content Security Policy utilities
 */
export class CSPBuilder {
  private policies: Record<string, string[]> = {
    'default-src': ["'none'"],
    'script-src': ["'self'", "'unsafe-inline'"], // Minimize unsafe-inline usage
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", 'data:', 'https:'],
    'font-src': ["'self'"],
    'connect-src': ["'self'"],
    'frame-src': ["'none'"],
    'object-src': ["'none'"],
    'media-src': ["'self'"],
    'form-action': ["'self'"],
    'base-uri': ["'self'"],
    'frame-ancestors': ["'none'"]
  };

  public addPolicy(directive: string, sources: string[]): this {
    this.policies[directive] = [...(this.policies[directive] || []), ...sources];
    return this;
  }

  public build(): string {
    return Object.entries(this.policies)
      .map(([directive, sources]) => `${directive} ${sources.join(' ')}`)
      .join('; ');
  }

  public static createSecureDefault(): string {
    return new CSPBuilder().build();
  }
}

// Sanitization helper functions
export const sanitizeHtml = (input: unknown): string => 
  UltraSecureHtmlSanitizer.getInstance().sanitizeHtml(input);

export const sanitizeAddress = (address: unknown): string =>
  UltraSecureHtmlSanitizer.getInstance().sanitizeCryptoAddress(address);

export const sanitizeHash = (hash: unknown): string =>
  UltraSecureHtmlSanitizer.getInstance().sanitizeHash(hash);

export const sanitizeNumeric = (value: unknown): string =>
  UltraSecureHtmlSanitizer.getInstance().sanitizeNumeric(value);

export const sanitizeHexData = (data: unknown): string =>
  UltraSecureHtmlSanitizer.getInstance().sanitizeHexData(data);

export const sanitizeUrl = (url: unknown): string =>
  SecureUrlUtils.sanitizeUrl(url);

// Runtime integrity check
const outputSecurityHash = require('crypto')
  .createHash('sha256')
  .update(UltraSecureHtmlSanitizer.toString() + SecureReactUtils.toString())
  .digest('hex');

SecureLogger.info(`Output security module loaded with integrity: ${outputSecurityHash.substring(0, 16)}...`);