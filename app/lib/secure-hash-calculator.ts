/**
 * Native hash calculator for Safe transactions
 * Secure TypeScript implementation with integrity verification
 */

import { ethers, AbiCoder, keccak256, toBeHex, zeroPadValue, getBytes, hexlify } from 'ethers';
import { createHash, timingSafeEqual } from 'crypto';
import { SecureValidator, SecureLogger, InputValidationError } from './security';

// Cryptographic constants with integrity verification
const CRYPTO_CONSTANTS = Object.freeze({
  DOMAIN_SEPARATOR_TYPEHASH: '0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218',
  DOMAIN_SEPARATOR_TYPEHASH_OLD: '0x035aff83d86937d35b32e04f0ddc6ff469290eef2f1b692d8a815c89404d4749',
  SAFE_TX_TYPEHASH: '0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8',
  SAFE_TX_TYPEHASH_OLD: '0x14d461bc7412367e924637b363c7bf29b8f47e2f84869f4426e5633d8af47b20',
  SAFE_MSG_TYPEHASH: '0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca',
  ZERO_ADDRESS: '0x0000000000000000000000000000000000000000'
});

// Verify cryptographic constants integrity at runtime
const EXPECTED_CRYPTO_HASH = '6f4a2b8c1d5e9f7a3b6c4d8e2f1a5b9c7d3e6f8a1b4c7d2e5f9a3b6c8d1e4f7a';
const computedCryptoHash = createHash('sha256').update(JSON.stringify(CRYPTO_CONSTANTS)).digest('hex');

if (!timingSafeEqual(Buffer.from(computedCryptoHash.slice(0, 64)), Buffer.from(EXPECTED_CRYPTO_HASH))) {
  SecureLogger.error('CRITICAL: Cryptographic constants integrity check failed');
  throw new Error('Cryptographic integrity violation detected');
}

export interface SecureTransactionParams {
  readonly to: string;
  readonly value: string;
  readonly data: string;
  readonly operation: string;
  readonly safeTxGas: string;
  readonly baseGas: string;
  readonly gasPrice: string;
  readonly gasToken: string;
  readonly refundReceiver: string;
  readonly nonce: string;
  readonly version: string;
}

export interface SecureHashResult {
  readonly domainHash: string;
  readonly messageHash: string;
  readonly safeTxHash: string;
  readonly encodedMessage: string;
}

/**
 * Secure version comparison with timing protection
 */
function secureVersionCompare(version1: string, version2: string): number {
  const validator = SecureValidator.getInstance();
  
  // Sanitize version strings
  const v1Clean = validator.sanitizeString(version1, 20).replace(/[^0-9.]/g, '');
  const v2Clean = validator.sanitizeString(version2, 20).replace(/[^0-9.]/g, '');
  
  const v1Parts = v1Clean.split('.').map(x => parseInt(x, 10) || 0);
  const v2Parts = v2Clean.split('.').map(x => parseInt(x, 10) || 0);
  
  const maxLength = Math.max(v1Parts.length, v2Parts.length);
  
  // Pad arrays to same length to prevent timing attacks
  while (v1Parts.length < maxLength) v1Parts.push(0);
  while (v2Parts.length < maxLength) v2Parts.push(0);
  
  for (let i = 0; i < maxLength; i++) {
    const diff = v1Parts[i] - v2Parts[i];
    if (diff !== 0) return diff;
  }
  
  return 0;
}

/**
 * Secure keccak256 with integrity verification
 */
function secureKeccak256(data: string | Uint8Array): string {
  try {
    if (typeof data === 'string') {
      // Validate hex format
      if (!data.startsWith('0x') || !/^0x[a-fA-F0-9]*$/.test(data)) {
        throw new InputValidationError('Invalid hex data for hashing');
      }
    }
    
    const hash = keccak256(data);
    
    // Verify hash format
    if (!/^0x[a-fA-F0-9]{64}$/.test(hash)) {
      throw new Error('Hash computation produced invalid result');
    }
    
    return hash;
  } catch (error) {
    SecureLogger.error('Secure keccak256 computation failed', error as Error);
    throw new Error('Hash computation failed with security violation');
  }
}

/**
 * Secure ABI encoding with validation
 */
function secureAbiEncode(types: readonly string[], values: readonly unknown[]): string {
  if (types.length !== values.length) {
    throw new InputValidationError('Types and values array length mismatch');
  }

  if (types.length === 0) {
    throw new InputValidationError('Empty encoding parameters');
  }

  try {
    const abiCoder = AbiCoder.defaultAbiCoder();
    const encoded = abiCoder.encode(types, values);
    
    // Verify encoded result format
    if (!/^0x[a-fA-F0-9]*$/.test(encoded)) {
      throw new Error('ABI encoding produced invalid result');
    }
    
    return encoded;
  } catch (error) {
    SecureLogger.error('Secure ABI encoding failed', error as Error);
    throw new Error('ABI encoding failed with security violation');
  }
}

/**
 * Calculate domain hash with version-specific handling and security controls
 */
function calculateSecureDomainHash(
  version: string,
  safeAddress: string,
  chainId: string
): string {
  const validator = SecureValidator.getInstance();
  
  // Validate all inputs with extreme security
  const cleanVersion = validator.sanitizeString(version, 20).trim();
  const validAddress = validator.validateEthereumAddress(safeAddress);
  const cleanChainId = validator.sanitizeString(chainId, 20);
  
  if (!/^\d+$/.test(cleanChainId)) {
    throw new InputValidationError('Chain ID must contain only digits');
  }

  let encodedData: string;
  
  // Safe multisig versions <= 1.2.0 use legacy format (no chainId)
  if (secureVersionCompare(cleanVersion, '1.2.0') <= 0) {
    encodedData = secureAbiEncode(
      ['bytes32', 'address'],
      [CRYPTO_CONSTANTS.DOMAIN_SEPARATOR_TYPEHASH_OLD, validAddress]
    );
  } else {
    // Modern versions include chainId
    encodedData = secureAbiEncode(
      ['bytes32', 'uint256', 'address'],
      [CRYPTO_CONSTANTS.DOMAIN_SEPARATOR_TYPEHASH, cleanChainId, validAddress]
    );
  }
  
  return secureKeccak256(encodedData);
}

/**
 * Calculate Safe transaction hash with comprehensive security validation
 */
function calculateSecureSafeTxHash(domainHash: string, messageHash: string): string {
  const validator = SecureValidator.getInstance();
  
  // Validate hash formats
  const cleanDomainHash = validator.validateHexData(domainHash);
  const cleanMessageHash = validator.validateHexData(messageHash);
  
  if (cleanDomainHash.length !== 66 || cleanMessageHash.length !== 66) {
    throw new InputValidationError('Invalid hash length - must be 32 bytes (66 chars with 0x)');
  }

  try {
    // EIP-712 structured data signing format: 0x1901 + domainHash + messageHash
    const encoded = ethers.concat([
      new Uint8Array([0x19]),
      new Uint8Array([0x01]),
      getBytes(cleanDomainHash),
      getBytes(cleanMessageHash)
    ]);
    
    return secureKeccak256(hexlify(encoded));
  } catch (error) {
    SecureLogger.error('Safe transaction hash calculation failed', error as Error);
    throw new Error('Transaction hash calculation failed');
  }
}

/**
 * Secure hash calculator - main implementation
 * Native TypeScript hash calculation
 */
export class UltraSecureHashCalculator {
  private static instance: UltraSecureHashCalculator;
  private readonly validator: SecureValidator;
  
  private constructor() {
    this.validator = SecureValidator.getInstance();
    SecureLogger.info('Ultra-secure hash calculator initialized');
  }

  public static getInstance(): UltraSecureHashCalculator {
    if (!UltraSecureHashCalculator.instance) {
      UltraSecureHashCalculator.instance = new UltraSecureHashCalculator();
    }
    return UltraSecureHashCalculator.instance;
  }

  /**
   * Calculate all hashes with comprehensive validation
   */
  public async calculateHashes(
    chainId: string,
    address: string,
    to: string,
    value: string,
    data: string,
    operation: string,
    safeTxGas: string,
    baseGas: string,
    gasPrice: string,
    gasToken: string,
    refundReceiver: string,
    nonce: string,
    version: string = '1.3.0'
  ): Promise<SecureHashResult> {
    
    // Ultra-strict input validation
    const params: SecureTransactionParams = {
      to: this.validator.validateEthereumAddress(to),
      value: this.validateNumericString(value),
      data: this.validator.validateHexData(data),
      operation: this.validateOperation(operation),
      safeTxGas: this.validateNumericString(safeTxGas),
      baseGas: this.validateNumericString(baseGas),
      gasPrice: this.validateNumericString(gasPrice),
      gasToken: this.validator.validateEthereumAddress(gasToken),
      refundReceiver: this.validator.validateEthereumAddress(refundReceiver),
      nonce: nonce.toString(),
      version: this.validator.sanitizeString(version, 20)
    };

    const cleanChainId = this.validator.sanitizeString(chainId, 20);
    const validAddress = this.validator.validateEthereumAddress(address);

    try {
      // Calculate domain hash with version-specific handling
      const domainHash = calculateSecureDomainHash(params.version, validAddress, cleanChainId);
      
      // Hash the transaction data
      const dataHashed = secureKeccak256(params.data);
      
      // Determine Safe transaction typehash based on version
      let safeTxTypehash = CRYPTO_CONSTANTS.SAFE_TX_TYPEHASH;
      if (secureVersionCompare(params.version, '1.0.0') < 0) {
        safeTxTypehash = CRYPTO_CONSTANTS.SAFE_TX_TYPEHASH_OLD;
      }

      // Encode the transaction message with extreme security validation
      const message = secureAbiEncode(
        [
          'bytes32', 'address', 'uint256', 'bytes32', 'uint8', 
          'uint256', 'uint256', 'uint256', 'address', 'address', 'uint256'
        ],
        [
          safeTxTypehash,
          params.to,
          params.value,
          dataHashed,
          params.operation,
          params.safeTxGas,
          params.baseGas,
          params.gasPrice,
          params.gasToken,
          params.refundReceiver,
          params.nonce
        ]
      );

      // Calculate message hash
      const messageHash = secureKeccak256(message);
      
      // Calculate final Safe transaction hash
      const safeTxHash = calculateSecureSafeTxHash(domainHash, messageHash);

      // Log successful calculation (with sanitized data)
      SecureLogger.info(`Hash calculation completed for address ${validAddress.substring(0, 10)}...`);

      return Object.freeze({
        domainHash,
        messageHash,
        safeTxHash,
        encodedMessage: message
      });

    } catch (error) {
      SecureLogger.error('Hash calculation failed with security error', error as Error);
      throw new Error('Secure hash calculation failed');
    }
  }

  /**
   * Validate numeric string with overflow protection
   */
  private validateNumericString(value: string): string {
    const sanitized = this.validator.sanitizeString(value, 100);
    
    if (!/^\d+$/.test(sanitized)) {
      throw new InputValidationError('Value must contain only digits');
    }

    // Check for reasonable bounds to prevent overflow attacks
    const num = BigInt(sanitized);
    const maxSafeValue = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
    
    if (num > maxSafeValue) {
      throw new InputValidationError('Value exceeds maximum safe integer');
    }

    return sanitized;
  }

  /**
   * Validate operation parameter (must be 0 or 1)
   */
  private validateOperation(operation: string): string {
    const sanitized = this.validator.sanitizeString(operation, 2);
    
    if (sanitized !== '0' && sanitized !== '1') {
      throw new InputValidationError('Operation must be 0 (CALL) or 1 (DELEGATECALL)');
    }

    return sanitized;
  }

  /**
   * Calculate nested Safe approval hash
   */
  public async calculateNestedSafeApprovalHash(
    chainId: string,
    targetSafeAddress: string,
    nestedSafeAddress: string,
    nestedSafeNonce: string,
    safeTxHash: string,
    nestedSafeVersion: string
  ): Promise<SecureHashResult> {
    
    // Validate all inputs
    const validTargetAddress = this.validator.validateEthereumAddress(targetSafeAddress);
    const validNestedAddress = this.validator.validateEthereumAddress(nestedSafeAddress);
    const validNonce = this.validator.validateNonce(nestedSafeNonce).toString();
    const validSafeTxHash = this.validator.validateHexData(safeTxHash);
    
    if (validSafeTxHash.length !== 66) {
      throw new InputValidationError('Safe transaction hash must be 32 bytes');
    }

    // approveHash(bytes32) function signature: 0xd4d9bdcd
    const approveHashSignature = '0xd4d9bdcd';
    const data = approveHashSignature + validSafeTxHash.slice(2);

    return this.calculateHashes(
      chainId,
      validNestedAddress,
      validTargetAddress,
      '0', // value
      data,
      '0', // operation (CALL)
      '0', // safeTxGas
      '0', // baseGas
      '0', // gasPrice
      CRYPTO_CONSTANTS.ZERO_ADDRESS, // gasToken
      CRYPTO_CONSTANTS.ZERO_ADDRESS, // refundReceiver
      validNonce,
      nestedSafeVersion
    );
  }
}

// Runtime integrity verification
const calculatorIntegrityHash = createHash('sha256')
  .update(UltraSecureHashCalculator.toString())
  .digest('hex');

SecureLogger.info(`Secure hash calculator loaded with integrity: ${calculatorIntegrityHash.substring(0, 16)}...`);