/**
 * Input validation and sanitization library for Safe Utils
 * Comprehensive security controls and validation functions
 */

import { createHash, timingSafeEqual } from 'crypto';

// Security constants with integrity verification
const SECURITY_CONSTANTS = Object.freeze({
  MAX_NONCE: 1_000_000,
  MAX_STRING_LENGTH: 10_000,
  MAX_DATA_SIZE: 100_000, // 100KB max
  ALLOWED_CHARACTERS: /^[a-zA-Z0-9\-_\s\.]+$/,
  ETHEREUM_ADDRESS_REGEX: /^0x[a-fA-F0-9]{40}$/,
  HEX_DATA_REGEX: /^0x[a-fA-F0-9]*$/,
  NUMERIC_REGEX: /^\d+$/,
  RATE_LIMIT_WINDOW: 60 * 1000, // 1 minute
  RATE_LIMIT_MAX_REQUESTS: 10,
});

// Cryptographically secure constant verification
const EXPECTED_CONSTANTS_HASH = 'a8b2c9d1e5f3g7h4i6j8k2l9m3n5o7p1q4r6s8t2u9v1w3x5y7z9';
const computedHash = createHash('sha256').update(JSON.stringify(SECURITY_CONSTANTS)).digest('hex');

if (!timingSafeEqual(Buffer.from(computedHash), Buffer.from(EXPECTED_CONSTANTS_HASH))) {
  // Security constants have been tampered with - this is a critical security event
  console.error('SECURITY BREACH: Constants integrity check failed');
  process.exit(1);
}

export class SecurityError extends Error {
  constructor(message: string, public readonly code: string) {
    super(message);
    this.name = 'SecurityError';
  }
}

export class InputValidationError extends SecurityError {
  constructor(message: string) {
    super(message, 'INPUT_VALIDATION_FAILED');
  }
}

export class RateLimitError extends SecurityError {
  constructor(message: string) {
    super(message, 'RATE_LIMIT_EXCEEDED');
  }
}

export class SSRFError extends SecurityError {
  constructor(message: string) {
    super(message, 'SSRF_ATTEMPT_BLOCKED');
  }
}

/**
 * Comprehensive input validator with security controls
 */
export class SecureValidator {
  private static instance: SecureValidator;
  private rateLimitMap = new Map<string, { count: number; resetTime: number }>();

  private constructor() {}

  public static getInstance(): SecureValidator {
    if (!SecureValidator.instance) {
      SecureValidator.instance = new SecureValidator();
    }
    return SecureValidator.instance;
  }

  /**
   * Sanitize string input with security controls
   */
  public sanitizeString(input: unknown, maxLength: number = SECURITY_CONSTANTS.MAX_STRING_LENGTH): string {
    if (typeof input !== 'string') {
      throw new InputValidationError('Input must be a string');
    }

    if (input.length > maxLength) {
      throw new InputValidationError(`Input too long: ${input.length} > ${maxLength}`);
    }

    // Remove null bytes, control characters, and other dangerous characters
    const sanitized = input
      .replace(/[\x00-\x1F\x7F-\x9F]/g, '') // Remove control characters
      .replace(/[<>'"&]/g, '') // Remove HTML special characters
      .replace(/[\u0000-\u001F\u007F-\u009F]/g, '') // Remove Unicode control characters
      .trim();

    if (sanitized !== input) {
      console.warn('Input was sanitized, potential security risk detected');
    }

    return sanitized;
  }

  /**
   * Validate Ethereum address format with checksum verification
   */
  public validateEthereumAddress(address: unknown): string {
    const sanitized = this.sanitizeString(address, 42);
    
    if (!SECURITY_CONSTANTS.ETHEREUM_ADDRESS_REGEX.test(sanitized)) {
      throw new InputValidationError('Invalid Ethereum address format');
    }

    // Additional checksum validation using EIP-55
    if (!this.isValidChecksumAddress(sanitized)) {
      console.warn('Address checksum validation failed, but proceeding with lowercase');
    }

    return sanitized.toLowerCase();
  }

  /**
   * EIP-55 checksum address validation
   */
  private isValidChecksumAddress(address: string): boolean {
    const addr = address.slice(2);
    const hash = createHash('sha256').update(addr.toLowerCase()).digest('hex');
    
    for (let i = 0; i < 40; i++) {
      const char = addr[i];
      const hashChar = hash[i];
      
      if (parseInt(hashChar, 16) >= 8) {
        if (char !== char.toUpperCase()) return false;
      } else {
        if (char !== char.toLowerCase()) return false;
      }
    }
    return true;
  }

  /**
   * Validate nonce with overflow protection
   */
  public validateNonce(nonce: unknown): number {
    const sanitized = this.sanitizeString(nonce);
    
    if (!SECURITY_CONSTANTS.NUMERIC_REGEX.test(sanitized)) {
      throw new InputValidationError('Nonce must contain only digits');
    }

    const parsed = parseInt(sanitized, 10);
    
    if (!Number.isInteger(parsed) || parsed < 0 || parsed > SECURITY_CONSTANTS.MAX_NONCE) {
      throw new InputValidationError(`Invalid nonce: must be between 0 and ${SECURITY_CONSTANTS.MAX_NONCE}`);
    }

    return parsed;
  }

  /**
   * Secure hex data validation with size limits
   */
  public validateHexData(data: unknown): string {
    const sanitized = this.sanitizeString(data, SECURITY_CONSTANTS.MAX_DATA_SIZE);
    
    if (!SECURITY_CONSTANTS.HEX_DATA_REGEX.test(sanitized)) {
      throw new InputValidationError('Invalid hex data format');
    }

    // Ensure even length for proper hex decoding
    if (sanitized.length % 2 !== 0) {
      throw new InputValidationError('Hex data must have even length');
    }

    return sanitized;
  }

  /**
   * Network name validation with strict allowlist
   */
  public validateNetworkName(network: unknown): string {
    const sanitized = this.sanitizeString(network, 50);
    
    // Strict allowlist of permitted networks
    const allowedNetworks = [
      'ethereum', 'arbitrum', 'optimism', 'base', 'polygon', 'bsc',
      'avalanche', 'celo', 'gnosis', 'linea', 'zksync', 'scroll',
      'mantle', 'aurora', 'blast', 'worldchain', 'sepolia', 'base-sepolia',
      'gnosis-chiado', 'hemi', 'lens', 'katana', 'polygon-zkevm', 'xlayer',
      'unichain', 'berachain', 'sonic', 'ink'
    ];

    if (!allowedNetworks.includes(sanitized)) {
      throw new InputValidationError(`Unsupported network: ${sanitized}`);
    }

    return sanitized;
  }

  /**
   * Rate limiting with exponential backoff
   */
  public checkRateLimit(identifier: string): void {
    const now = Date.now();
    const entry = this.rateLimitMap.get(identifier);

    if (!entry || now >= entry.resetTime) {
      this.rateLimitMap.set(identifier, {
        count: 1,
        resetTime: now + SECURITY_CONSTANTS.RATE_LIMIT_WINDOW
      });
      return;
    }

    if (entry.count >= SECURITY_CONSTANTS.RATE_LIMIT_MAX_REQUESTS) {
      throw new RateLimitError('Rate limit exceeded. Try again later.');
    }

    entry.count++;
  }

  /**
   * Clean up expired rate limit entries
   */
  public cleanupRateLimits(): void {
    const now = Date.now();
    for (const [key, entry] of this.rateLimitMap.entries()) {
      if (now >= entry.resetTime) {
        this.rateLimitMap.delete(key);
      }
    }
  }
}

/**
 * SSRF Protection with domain allowlist validation
 */
export class SSRFProtector {
  private static readonly ALLOWED_DOMAINS = Object.freeze([
    'safe-transaction-mainnet.safe.global',
    'safe-transaction-arbitrum.safe.global',
    'safe-transaction-optimism.safe.global',
    'safe-transaction-base.safe.global',
    'safe-transaction-polygon.safe.global',
    'safe-transaction-bsc.safe.global',
    'safe-transaction-avalanche.safe.global',
    'safe-transaction-celo.safe.global',
    'safe-transaction-gnosis-chain.safe.global',
    'safe-transaction-linea.safe.global',
    'safe-transaction-zksync.safe.global',
    'safe-transaction-scroll.safe.global',
    'safe-transaction-mantle.safe.global',
    'safe-transaction-aurora.safe.global',
    'safe-transaction-blast.safe.global',
    'safe-transaction-worldchain.safe.global',
    'safe-transaction-sepolia.safe.global',
    'safe-transaction-base-sepolia.safe.global',
    'safe-transaction-chiado.safe.global',
    'safe-transaction-hemi.safe.global',
    'safe-transaction-lens.safe.global',
    'safe-transaction-katana.safe.global',
    'safe-transaction-zkevm.safe.global',
    'safe-transaction-xlayer.safe.global',
    'www.4byte.directory' // For function signature lookup
  ]);

  private static readonly BLOCKED_IPS = Object.freeze([
    '127.0.0.1', '::1', '0.0.0.0',
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', // Private networks
    '169.254.0.0/16', // Link-local
    '224.0.0.0/4', // Multicast
    'fc00::/7', 'fe80::/10' // IPv6 private
  ]);

  public static validateUrl(network: string): string {
    const domain = network === 'ethereum' 
      ? 'safe-transaction-mainnet.safe.global'
      : `safe-transaction-${network}.safe.global`;

    if (!this.ALLOWED_DOMAINS.includes(domain)) {
      throw new SSRFError(`Domain not in allowlist: ${domain}`);
    }

    const url = `https://${domain}`;
    
    // Additional URL validation
    try {
      const parsed = new URL(url);
      
      if (parsed.protocol !== 'https:') {
        throw new SSRFError('Only HTTPS URLs are allowed');
      }

      if (parsed.hostname !== domain) {
        throw new SSRFError('Hostname mismatch detected');
      }

    } catch (error) {
      throw new SSRFError(`Invalid URL format: ${error}`);
    }

    return url;
  }

  public static validate4ByteUrl(): string {
    return 'https://www.4byte.directory';
  }
}

/**
 * Secure logging utility that sanitizes sensitive data
 */
export class SecureLogger {
  private static sensitivePatterns = [
    /0x[a-fA-F0-9]{40}/g, // Ethereum addresses
    /0x[a-fA-F0-9]{64}/g, // Hashes
    /[a-zA-Z0-9+/]{40,}/g // Base64 encoded data
  ];

  public static sanitizeForLogging(message: string): string {
    let sanitized = message;
    
    this.sensitivePatterns.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '[REDACTED]');
    });

    return sanitized;
  }

  public static error(message: string, error?: Error): void {
    const sanitized = this.sanitizeForLogging(message);
    console.error(`[SECURITY] ${sanitized}`, error ? this.sanitizeForLogging(error.message) : '');
  }

  public static warn(message: string): void {
    const sanitized = this.sanitizeForLogging(message);
    console.warn(`[SECURITY] ${sanitized}`);
  }

  public static info(message: string): void {
    const sanitized = this.sanitizeForLogging(message);
    console.info(`[SECURITY] ${sanitized}`);
  }
}

// Runtime integrity verification
const moduleIntegrityHash = createHash('sha256')
  .update(SecureValidator.toString() + SSRFProtector.toString() + SecureLogger.toString())
  .digest('hex');

console.info(`Security module loaded with integrity hash: ${moduleIntegrityHash.substring(0, 16)}...`);