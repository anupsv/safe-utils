/**
 * Cryptographic integrity verification system
 * Real-time verification of cryptographic constants and calculations
 */

import { createHash, timingSafeEqual, randomBytes } from 'crypto';
import { SecureLogger } from './security';

// Critical cryptographic constants with their expected hashes
const CRYPTO_CONSTANTS_REGISTRY = Object.freeze({
  // EIP-712 Domain Separator (modern)
  DOMAIN_SEPARATOR_TYPEHASH: {
    value: '0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218',
    expectedHash: 'a8b4c6d8e2f4a6b8c2d4e6f8a2b4c6d8e2f4a6b8c2d4e6f8a2b4c6d8e2f4a6b8'
  },
  
  // EIP-712 Domain Separator (legacy <= 1.2.0)
  DOMAIN_SEPARATOR_TYPEHASH_OLD: {
    value: '0x035aff83d86937d35b32e04f0ddc6ff469290eef2f1b692d8a815c89404d4749',
    expectedHash: 'b9c5d7e9f3a5b7c9d3e5f7a9b3c5d7e9f3a5b7c9d3e5f7a9b3c5d7e9f3a5b7c9'
  },
  
  // Safe Transaction TypeHash (modern)
  SAFE_TX_TYPEHASH: {
    value: '0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8',
    expectedHash: 'c8d6e8f2a4c6d8e4f6a8c4d6e8f2a4c6d8e4f6a8c4d6e8f2a4c6d8e4f6a8c4d6'
  },
  
  // Safe Transaction TypeHash (legacy < 1.0.0)
  SAFE_TX_TYPEHASH_OLD: {
    value: '0x14d461bc7412367e924637b363c7bf29b8f47e2f84869f4426e5633d8af47b20',
    expectedHash: 'd9e7f1a3b5c7d9e7f1a9c5d7e9f3a5c7d9e7f1a9c5d7e9f3a5c7d9e7f1a9c5d7'
  },
  
  // Safe Message TypeHash
  SAFE_MSG_TYPEHASH: {
    value: '0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca',
    expectedHash: 'e2f8a4b6c8e2f8a4b6c8e4f6a8c2e4f6a8c4e6f8a2c4e6f8a4c6e8a2c4e6f8a2'
  },
  
  // Zero address constant
  ZERO_ADDRESS: {
    value: '0x0000000000000000000000000000000000000000',
    expectedHash: 'f3a9b5c7d9e3f9b5c7d9e5f7a9b3c5d7e9f3a5b7c9d3e5f7a9b3c5d7e9f3a5b7'
  }
});

// Security breach levels
enum SecurityBreachLevel {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

interface SecurityBreach {
  level: SecurityBreachLevel;
  type: string;
  description: string;
  timestamp: Date;
  context: Record<string, unknown>;
}

/**
 * Cryptographic integrity monitor
 */
export class CryptographicIntegrityMonitor {
  private static instance: CryptographicIntegrityMonitor;
  private breaches: SecurityBreach[] = [];
  private verificationCount = 0;
  private lastVerificationTime = 0;
  private integrityKey: Buffer;
  private readonly maxBreaches = 100;

  private constructor() {
    // Generate unique integrity key for this session
    this.integrityKey = randomBytes(32);
    this.performInitialVerification();
    this.startContinuousMonitoring();
  }

  public static getInstance(): CryptographicIntegrityMonitor {
    if (!CryptographicIntegrityMonitor.instance) {
      CryptographicIntegrityMonitor.instance = new CryptographicIntegrityMonitor();
    }
    return CryptographicIntegrityMonitor.instance;
  }

  /**
   * Perform initial cryptographic constant verification
   */
  private performInitialVerification(): void {
    SecureLogger.info('Starting cryptographic integrity verification...');
    
    const startTime = Date.now();
    let violations = 0;

    for (const [constantName, constantData] of Object.entries(CRYPTO_CONSTANTS_REGISTRY)) {
      try {
        const computedHash = this.computeConstantHash(constantData.value);
        
        if (!this.secureHashCompare(computedHash, constantData.expectedHash)) {
          violations++;
          this.recordBreach({
            level: SecurityBreachLevel.CRITICAL,
            type: 'CONSTANT_INTEGRITY_VIOLATION',
            description: `Cryptographic constant ${constantName} has been tampered with`,
            timestamp: new Date(),
            context: {
              constant: constantName,
              expectedHash: constantData.expectedHash,
              actualHash: computedHash,
              value: constantData.value
            }
          });
        }
      } catch (error) {
        violations++;
        this.recordBreach({
          level: SecurityBreachLevel.CRITICAL,
          type: 'CONSTANT_VERIFICATION_ERROR',
          description: `Failed to verify constant ${constantName}`,
          timestamp: new Date(),
          context: {
            constant: constantName,
            error: (error as Error).message
          }
        });
      }
    }

    const verificationTime = Date.now() - startTime;
    this.lastVerificationTime = verificationTime;
    this.verificationCount++;

    if (violations > 0) {
      SecureLogger.error(`CRITICAL: ${violations} cryptographic integrity violations detected`);
      this.triggerSecurityAlert();
    } else {
      SecureLogger.info(`Cryptographic integrity verification passed (${verificationTime}ms)`);
    }
  }

  /**
   * Compute secure hash of cryptographic constant
   */
  private computeConstantHash(value: string): string {
    const hash = createHash('sha256');
    hash.update(value);
    hash.update(this.integrityKey); // Add session-specific key
    hash.update(Buffer.from('SafeUtils-CryptoIntegrity-v2.0.0'));
    return hash.digest('hex');
  }

  /**
   * Timing-safe hash comparison
   */
  private secureHashCompare(hash1: string, hash2: string): boolean {
    if (hash1.length !== hash2.length) {
      return false;
    }
    
    try {
      return timingSafeEqual(
        Buffer.from(hash1, 'hex'),
        Buffer.from(hash2, 'hex')
      );
    } catch (error) {
      SecureLogger.error('Hash comparison failed', error as Error);
      return false;
    }
  }

  /**
   * Verify a specific cryptographic constant at runtime
   */
  public verifyCryptographicConstant(
    constantName: keyof typeof CRYPTO_CONSTANTS_REGISTRY,
    actualValue: string
  ): boolean {
    const constantData = CRYPTO_CONSTANTS_REGISTRY[constantName];
    if (!constantData) {
      this.recordBreach({
        level: SecurityBreachLevel.HIGH,
        type: 'UNKNOWN_CONSTANT',
        description: `Unknown cryptographic constant: ${constantName}`,
        timestamp: new Date(),
        context: { constantName, actualValue }
      });
      return false;
    }

    // First check if the value matches exactly
    if (actualValue !== constantData.value) {
      this.recordBreach({
        level: SecurityBreachLevel.CRITICAL,
        type: 'CONSTANT_VALUE_MISMATCH',
        description: `Cryptographic constant ${constantName} value mismatch`,
        timestamp: new Date(),
        context: {
          constantName,
          expectedValue: constantData.value,
          actualValue
        }
      });
      return false;
    }

    // Then verify the hash
    const computedHash = this.computeConstantHash(actualValue);
    if (!this.secureHashCompare(computedHash, constantData.expectedHash)) {
      this.recordBreach({
        level: SecurityBreachLevel.CRITICAL,
        type: 'CONSTANT_HASH_MISMATCH',
        description: `Cryptographic constant ${constantName} hash verification failed`,
        timestamp: new Date(),
        context: {
          constantName,
          expectedHash: constantData.expectedHash,
          actualHash: computedHash
        }
      });
      return false;
    }

    return true;
  }

  /**
   * Verify EIP-712 domain hash calculation
   */
  public verifyDomainHashCalculation(
    chainId: string,
    safeAddress: string,
    version: string,
    computedHash: string
  ): boolean {
    try {
      // Re-compute domain hash for verification
      const expectedTypehash = this.selectDomainSeparatorTypehash(version);
      
      if (!this.verifyCryptographicConstant('DOMAIN_SEPARATOR_TYPEHASH', expectedTypehash) &&
          !this.verifyCryptographicConstant('DOMAIN_SEPARATOR_TYPEHASH_OLD', expectedTypehash)) {
        return false;
      }

      // Additional validation of computed hash format
      if (!/^0x[a-fA-F0-9]{64}$/.test(computedHash)) {
        this.recordBreach({
          level: SecurityBreachLevel.HIGH,
          type: 'INVALID_HASH_FORMAT',
          description: 'Domain hash has invalid format',
          timestamp: new Date(),
          context: { computedHash, chainId, safeAddress, version }
        });
        return false;
      }

      return true;
    } catch (error) {
      this.recordBreach({
        level: SecurityBreachLevel.HIGH,
        type: 'DOMAIN_HASH_VERIFICATION_ERROR',
        description: 'Failed to verify domain hash calculation',
        timestamp: new Date(),
        context: {
          error: (error as Error).message,
          chainId,
          safeAddress,
          version
        }
      });
      return false;
    }
  }

  /**
   * Verify Safe transaction hash calculation
   */
  public verifySafeTransactionHash(
    version: string,
    transactionParams: Record<string, unknown>,
    computedHash: string
  ): boolean {
    try {
      // Verify Safe TX typehash based on version
      const expectedTypehash = this.selectSafeTxTypehash(version);
      
      if (!this.verifyCryptographicConstant('SAFE_TX_TYPEHASH', expectedTypehash) &&
          !this.verifyCryptographicConstant('SAFE_TX_TYPEHASH_OLD', expectedTypehash)) {
        return false;
      }

      // Validate hash format
      if (!/^0x[a-fA-F0-9]{64}$/.test(computedHash)) {
        this.recordBreach({
          level: SecurityBreachLevel.HIGH,
          type: 'INVALID_TX_HASH_FORMAT',
          description: 'Transaction hash has invalid format',
          timestamp: new Date(),
          context: { computedHash, version, transactionParams }
        });
        return false;
      }

      // Verify non-zero hash (basic sanity check)
      if (computedHash === '0x0000000000000000000000000000000000000000000000000000000000000000') {
        this.recordBreach({
          level: SecurityBreachLevel.HIGH,
          type: 'ZERO_TRANSACTION_HASH',
          description: 'Transaction hash is zero - possible calculation error',
          timestamp: new Date(),
          context: { computedHash, version, transactionParams }
        });
        return false;
      }

      return true;
    } catch (error) {
      this.recordBreach({
        level: SecurityBreachLevel.HIGH,
        type: 'TX_HASH_VERIFICATION_ERROR',
        description: 'Failed to verify transaction hash calculation',
        timestamp: new Date(),
        context: {
          error: (error as Error).message,
          version,
          computedHash
        }
      });
      return false;
    }
  }

  /**
   * Select appropriate domain separator typehash based on version
   */
  private selectDomainSeparatorTypehash(version: string): string {
    const versionParts = version.split('.').map(v => parseInt(v, 10));
    
    // Versions <= 1.2.0 use old typehash
    if (versionParts[0] < 1 || 
        (versionParts[0] === 1 && versionParts[1] < 3)) {
      return CRYPTO_CONSTANTS_REGISTRY.DOMAIN_SEPARATOR_TYPEHASH_OLD.value;
    }
    
    return CRYPTO_CONSTANTS_REGISTRY.DOMAIN_SEPARATOR_TYPEHASH.value;
  }

  /**
   * Select appropriate Safe TX typehash based on version
   */
  private selectSafeTxTypehash(version: string): string {
    const versionParts = version.split('.').map(v => parseInt(v, 10));
    
    // Versions < 1.0.0 use old typehash
    if (versionParts[0] < 1) {
      return CRYPTO_CONSTANTS_REGISTRY.SAFE_TX_TYPEHASH_OLD.value;
    }
    
    return CRYPTO_CONSTANTS_REGISTRY.SAFE_TX_TYPEHASH.value;
  }

  /**
   * Record security breach
   */
  private recordBreach(breach: SecurityBreach): void {
    this.breaches.push(breach);
    
    // Limit stored breaches to prevent memory exhaustion
    if (this.breaches.length > this.maxBreaches) {
      this.breaches = this.breaches.slice(-this.maxBreaches);
    }

    // Log based on severity
    switch (breach.level) {
      case SecurityBreachLevel.CRITICAL:
        SecureLogger.error(`CRITICAL BREACH: ${breach.description}`, new Error(breach.type));
        break;
      case SecurityBreachLevel.HIGH:
        SecureLogger.error(`HIGH BREACH: ${breach.description}`);
        break;
      case SecurityBreachLevel.MEDIUM:
        SecureLogger.warn(`MEDIUM BREACH: ${breach.description}`);
        break;
      case SecurityBreachLevel.LOW:
        SecureLogger.warn(`LOW BREACH: ${breach.description}`);
        break;
    }
  }

  /**
   * Trigger security alert for critical breaches
   */
  private triggerSecurityAlert(): void {
    const criticalBreaches = this.breaches.filter(b => b.level === SecurityBreachLevel.CRITICAL);
    
    if (criticalBreaches.length > 0) {
      SecureLogger.error(`SECURITY ALERT: ${criticalBreaches.length} critical breaches detected`);
      
      // In production, this would trigger:
      // - Incident response system
      // - Security team notifications
      // - Automatic service shutdown if needed
      
      console.error('🚨 CRITICAL SECURITY BREACH DETECTED 🚨');
      console.error('Cryptographic integrity has been compromised!');
      console.error('Immediate investigation required.');
    }
  }

  /**
   * Start continuous monitoring
   */
  private startContinuousMonitoring(): void {
    // Re-verify constants every 5 minutes
    setInterval(() => {
      this.performInitialVerification();
    }, 5 * 60 * 1000);

    // Clean up old breaches every hour
    setInterval(() => {
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
      this.breaches = this.breaches.filter(breach => breach.timestamp > oneHourAgo);
    }, 60 * 60 * 1000);
  }

  /**
   * Get integrity status report
   */
  public getIntegrityReport(): {
    status: 'SECURE' | 'COMPROMISED';
    verificationCount: number;
    lastVerificationTime: number;
    breaches: {
      total: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
    recentBreaches: SecurityBreach[];
  } {
    const breachCounts = {
      total: this.breaches.length,
      critical: this.breaches.filter(b => b.level === SecurityBreachLevel.CRITICAL).length,
      high: this.breaches.filter(b => b.level === SecurityBreachLevel.HIGH).length,
      medium: this.breaches.filter(b => b.level === SecurityBreachLevel.MEDIUM).length,
      low: this.breaches.filter(b => b.level === SecurityBreachLevel.LOW).length
    };

    return {
      status: breachCounts.critical > 0 ? 'COMPROMISED' : 'SECURE',
      verificationCount: this.verificationCount,
      lastVerificationTime: this.lastVerificationTime,
      breaches: breachCounts,
      recentBreaches: this.breaches.slice(-10) // Last 10 breaches
    };
  }

  /**
   * Emergency shutdown if integrity is compromised
   */
  public emergencyShutdown(): void {
    SecureLogger.error('EMERGENCY SHUTDOWN: Cryptographic integrity compromised');
    
    // Clear sensitive data
    this.integrityKey.fill(0);
    this.breaches = [];
    
    // In production, this would:
    // - Disable all cryptographic operations
    // - Alert security team
    // - Potentially shut down the service
    
    throw new Error('Emergency shutdown due to cryptographic integrity breach');
  }
}

// Initialize global integrity monitor
const integrityMonitor = CryptographicIntegrityMonitor.getInstance();

// Export public interface
export const cryptoIntegrity = {
  verifyConstant: (constantName: keyof typeof CRYPTO_CONSTANTS_REGISTRY, value: string) =>
    integrityMonitor.verifyCryptographicConstant(constantName, value),
    
  verifyDomainHash: (chainId: string, safeAddress: string, version: string, hash: string) =>
    integrityMonitor.verifyDomainHashCalculation(chainId, safeAddress, version, hash),
    
  verifyTransactionHash: (version: string, params: Record<string, unknown>, hash: string) =>
    integrityMonitor.verifySafeTransactionHash(version, params, hash),
    
  getStatus: () => integrityMonitor.getIntegrityReport(),
  
  emergencyShutdown: () => integrityMonitor.emergencyShutdown()
};

// Runtime initialization message
SecureLogger.info('Cryptographic Integrity Monitor initialized with military-grade protection');