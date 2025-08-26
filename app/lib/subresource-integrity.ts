/**
 * Subresource Integrity (SRI) verification and management system
 * Ensures external resources haven't been tampered with
 */

import { SecureLogger, SecurityError } from '@/lib/security';
import { processError } from '@/lib/secure-error-handler';
import { createHash } from 'crypto';

export interface SRIResource {
  url: string;
  integrity: string;
  crossorigin: 'anonymous' | 'use-credentials';
}

export interface SRIGenerationResult {
  integrity: string;
  algorithm: 'sha256' | 'sha384' | 'sha512';
  hash: string;
}

/**
 * Comprehensive SRI management system
 */
export class SubresourceIntegrityManager {
  private static instance: SubresourceIntegrityManager;
  private verifiedResources = new Map<string, SRIResource>();
  private failureCount = new Map<string, number>();
  private readonly MAX_FAILURES = 3;

  public static getInstance(): SubresourceIntegrityManager {
    if (!SubresourceIntegrityManager.instance) {
      SubresourceIntegrityManager.instance = new SubresourceIntegrityManager();
    }
    return SubresourceIntegrityManager.instance;
  }

  /**
   * Generate SRI hash for resource content
   */
  public generateSRIHash(content: string, algorithm: 'sha256' | 'sha384' | 'sha512' = 'sha384'): SRIGenerationResult {
    try {
      const hash = createHash(algorithm).update(content, 'utf8').digest('base64');
      const integrity = `${algorithm}-${hash}`;

      SecureLogger.info(`Generated SRI hash using ${algorithm}: ${integrity.substring(0, 20)}...`);

      return {
        integrity,
        algorithm,
        hash
      };
    } catch (error) {
      const secureError = processError(error, {
        algorithm,
        contentLength: content.length,
        context: 'sri_generation'
      });

      SecureLogger.error('SRI hash generation failed', error as Error);
      throw new SecurityError('Failed to generate SRI hash', 'SRI_GENERATION_FAILED');
    }
  }

  /**
   * Verify resource against expected SRI hash
   */
  public async verifyResourceIntegrity(url: string, content: string, expectedIntegrity: string): Promise<boolean> {
    try {
      // Parse integrity string (format: algorithm-hash)
      const integrityParts = expectedIntegrity.split('-');
      if (integrityParts.length !== 2) {
        throw new SecurityError('Invalid integrity format', 'INVALID_INTEGRITY_FORMAT');
      }

      const [algorithm, expectedHash] = integrityParts;
      
      // Validate algorithm
      if (!['sha256', 'sha384', 'sha512'].includes(algorithm)) {
        throw new SecurityError('Unsupported hash algorithm', 'UNSUPPORTED_ALGORITHM');
      }

      // Generate hash for content
      const actualHash = createHash(algorithm as any).update(content, 'utf8').digest('base64');
      const actualIntegrity = `${algorithm}-${actualHash}`;

      const isValid = actualIntegrity === expectedIntegrity;

      if (isValid) {
        this.verifiedResources.set(url, {
          url,
          integrity: expectedIntegrity,
          crossorigin: 'anonymous'
        });
        this.failureCount.delete(url);
        SecureLogger.info(`SRI verification successful for ${url}`);
      } else {
        const failures = (this.failureCount.get(url) || 0) + 1;
        this.failureCount.set(url, failures);

        SecureLogger.error(`SRI verification failed for ${url} (attempt ${failures}/${this.MAX_FAILURES})`);
        SecureLogger.error(`Expected: ${expectedIntegrity}`);
        SecureLogger.error(`Actual: ${actualIntegrity}`);

        if (failures >= this.MAX_FAILURES) {
          throw new SecurityError('Resource integrity verification failed repeatedly', 'SRI_VERIFICATION_FAILED');
        }
      }

      return isValid;
    } catch (error) {
      const secureError = processError(error, {
        url: url.substring(0, 100),
        expectedIntegrity: expectedIntegrity.substring(0, 50),
        context: 'sri_verification'
      });

      SecureLogger.error('SRI verification error', error as Error);
      return false;
    }
  }

  /**
   * Fetch and verify external resource with SRI
   */
  public async fetchVerifiedResource(url: string, expectedIntegrity: string, timeout: number = 10000): Promise<string> {
    try {
      // Validate URL format
      const parsedUrl = new URL(url);
      if (!['https:', 'http:'].includes(parsedUrl.protocol)) {
        throw new SecurityError('Only HTTP(S) URLs are supported', 'INVALID_PROTOCOL');
      }

      // Set up request with timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      try {
        const response = await fetch(url, {
          method: 'GET',
          headers: {
            'User-Agent': 'SafeUtils-SRI-Verifier/1.0.0',
            'Accept': '*/*',
            'Cache-Control': 'no-cache'
          },
          signal: controller.signal,
          redirect: 'error'
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          throw new SecurityError(`Resource fetch failed: ${response.status}`, 'FETCH_FAILED');
        }

        // Check content length
        const contentLength = response.headers.get('content-length');
        if (contentLength && parseInt(contentLength) > 5000000) { // 5MB max
          throw new SecurityError('Resource too large', 'RESOURCE_TOO_LARGE');
        }

        const content = await response.text();

        // Verify integrity
        const isValid = await this.verifyResourceIntegrity(url, content, expectedIntegrity);
        if (!isValid) {
          throw new SecurityError('Resource integrity verification failed', 'SRI_VERIFICATION_FAILED');
        }

        return content;
      } finally {
        clearTimeout(timeoutId);
      }
    } catch (error) {
      const secureError = processError(error, {
        url: url.substring(0, 100),
        expectedIntegrity: expectedIntegrity.substring(0, 50),
        context: 'sri_fetch'
      });

      SecureLogger.error('Verified resource fetch failed', error as Error);
      throw error;
    }
  }

  /**
   * Generate HTML script tag with SRI
   */
  public generateSecureScriptTag(src: string, integrity: string, crossorigin: 'anonymous' | 'use-credentials' = 'anonymous'): string {
    try {
      // Validate inputs
      const parsedUrl = new URL(src);
      if (!['https:', 'http:'].includes(parsedUrl.protocol)) {
        throw new SecurityError('Only HTTP(S) URLs are supported for script tags', 'INVALID_SCRIPT_URL');
      }

      // Validate integrity format
      if (!/^(sha256|sha384|sha512)-[A-Za-z0-9+/]+=*$/.test(integrity)) {
        throw new SecurityError('Invalid integrity format', 'INVALID_INTEGRITY_FORMAT');
      }

      // Generate secure script tag
      const scriptTag = `<script src="${src}" integrity="${integrity}" crossorigin="${crossorigin}"></script>`;
      
      SecureLogger.info(`Generated secure script tag for ${src}`);
      return scriptTag;
    } catch (error) {
      const secureError = processError(error, {
        src: src.substring(0, 100),
        integrity: integrity.substring(0, 50),
        context: 'script_tag_generation'
      });

      SecureLogger.error('Secure script tag generation failed', error as Error);
      throw error;
    }
  }

  /**
   * Generate HTML link tag with SRI for stylesheets
   */
  public generateSecureLinkTag(href: string, integrity: string, crossorigin: 'anonymous' | 'use-credentials' = 'anonymous'): string {
    try {
      // Validate inputs
      const parsedUrl = new URL(href);
      if (!['https:', 'http:'].includes(parsedUrl.protocol)) {
        throw new SecurityError('Only HTTP(S) URLs are supported for link tags', 'INVALID_LINK_URL');
      }

      // Validate integrity format
      if (!/^(sha256|sha384|sha512)-[A-Za-z0-9+/]+=*$/.test(integrity)) {
        throw new SecurityError('Invalid integrity format', 'INVALID_INTEGRITY_FORMAT');
      }

      // Generate secure link tag
      const linkTag = `<link rel="stylesheet" href="${href}" integrity="${integrity}" crossorigin="${crossorigin}">`;
      
      SecureLogger.info(`Generated secure link tag for ${href}`);
      return linkTag;
    } catch (error) {
      const secureError = processError(error, {
        href: href.substring(0, 100),
        integrity: integrity.substring(0, 50),
        context: 'link_tag_generation'
      });

      SecureLogger.error('Secure link tag generation failed', error as Error);
      throw error;
    }
  }

  /**
   * Get statistics about SRI verification
   */
  public getVerificationStats(): {
    verifiedCount: number;
    failedCount: number;
    totalFailures: number;
  } {
    const totalFailures = Array.from(this.failureCount.values()).reduce((sum, count) => sum + count, 0);

    return {
      verifiedCount: this.verifiedResources.size,
      failedCount: this.failureCount.size,
      totalFailures
    };
  }

  /**
   * Clear verification cache
   */
  public clearCache(): void {
    this.verifiedResources.clear();
    this.failureCount.clear();
    SecureLogger.info('SRI verification cache cleared');
  }
}

/**
 * Predefined SRI hashes for common CDN resources
 */
export const TRUSTED_CDN_RESOURCES: Record<string, SRIResource> = Object.freeze({
  'bootstrap-5.3.0-css': {
    url: 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css',
    integrity: 'sha384-9ndCyUa4KLGjhVqQqJgNRxNaJWVx3F6v2KO0Pma0LHn1RwA4EJWMPqz1V6Nq7VzJ',
    crossorigin: 'anonymous'
  },
  'bootstrap-5.3.0-js': {
    url: 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js',
    integrity: 'sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz',
    crossorigin: 'anonymous'
  },
  'jquery-3.7.1': {
    url: 'https://code.jquery.com/jquery-3.7.1.min.js',
    integrity: 'sha384-1H217gwSVyLSIfaLxHbE7dRb3v4mYCKbpQvzx0cegeju1MVsGrX5xXxAvs/HgeFs',
    crossorigin: 'anonymous'
  }
});

// Export singleton instance
export const SRIManager = SubresourceIntegrityManager.getInstance();

// Export as alias for backward compatibility
export const SubresourceIntegrity = SubresourceIntegrityManager;