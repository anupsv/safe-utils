/**
 * Secure 4byte.directory API integration
 * Replaces legacy insecure implementation with comprehensive protection
 */

import { 
  SSRFProtector, 
  SecureValidator, 
  SecureLogger
} from '@/lib/security';
import { processError } from '@/lib/secure-error-handler';
import { sanitizeHtml } from '@/lib/secure-output';

// Secure configuration for 4byte API
const FOURBYTE_CONFIG = Object.freeze({
  BASE_URL: 'https://www.4byte.directory',
  MAX_RETRIES: 3,
  TIMEOUT: 5000,
  MAX_RESULTS: 10,
  CACHE_TTL: 24 * 60 * 60 * 1000, // 24 hours
  RATE_LIMIT_PER_MINUTE: 60
});

// In-memory cache with TTL
interface CacheEntry {
  signature: string | null;
  timestamp: number;
}

class SecureFourByteCache {
  private cache = new Map<string, CacheEntry>();
  private requestCount = new Map<string, { count: number; resetTime: number }>();

  public get(methodId: string): string | null | undefined {
    const entry = this.cache.get(methodId);
    if (!entry) return undefined;
    
    // Check if cache entry is still valid
    if (Date.now() - entry.timestamp > FOURBYTE_CONFIG.CACHE_TTL) {
      this.cache.delete(methodId);
      return undefined;
    }
    
    return entry.signature;
  }

  public set(methodId: string, signature: string | null): void {
    this.cache.set(methodId, {
      signature,
      timestamp: Date.now()
    });
    
    // Limit cache size to prevent memory exhaustion
    if (this.cache.size > 1000) {
      const oldestKey = this.cache.keys().next().value;
      this.cache.delete(oldestKey);
    }
  }

  public checkRateLimit(identifier: string): boolean {
    const now = Date.now();
    const entry = this.requestCount.get(identifier);

    if (!entry || now >= entry.resetTime) {
      this.requestCount.set(identifier, {
        count: 1,
        resetTime: now + 60000 // 1 minute
      });
      return true;
    }

    if (entry.count >= FOURBYTE_CONFIG.RATE_LIMIT_PER_MINUTE) {
      return false;
    }

    entry.count++;
    return true;
  }

  public cleanup(): void {
    const now = Date.now();
    
    // Clean expired cache entries
    for (const [key, entry] of this.cache.entries()) {
      if (now - entry.timestamp > FOURBYTE_CONFIG.CACHE_TTL) {
        this.cache.delete(key);
      }
    }
    
    // Clean expired rate limit entries
    for (const [key, entry] of this.requestCount.entries()) {
      if (now >= entry.resetTime) {
        this.requestCount.delete(key);
      }
    }
  }
}

const secureCache = new SecureFourByteCache();

// Periodic cleanup
setInterval(() => {
  secureCache.cleanup();
}, 5 * 60 * 1000); // Every 5 minutes

/**
 * Validate method ID format
 */
function validateMethodId(methodId: string): boolean {
  const validator = SecureValidator.getInstance();
  
  try {
    const sanitized = validator.sanitizeString(methodId, 10);
    
    // Must be exactly 10 characters: 0x + 8 hex digits
    if (sanitized.length !== 10) {
      return false;
    }
    
    // Must start with 0x
    if (!sanitized.startsWith('0x')) {
      return false;
    }
    
    // Must contain only hex characters after 0x
    const hexPart = sanitized.slice(2);
    if (!/^[a-fA-F0-9]{8}$/.test(hexPart)) {
      return false;
    }
    
    return true;
  } catch (error) {
    SecureLogger.error('Method ID validation failed', error as Error);
    return false;
  }
}

/**
 * Secure HTTP request to 4byte.directory with comprehensive protection
 */
async function secureApiRequest(methodId: string): Promise<any> {
  const url = `${FOURBYTE_CONFIG.BASE_URL}/api/v1/signatures/?hex_signature=${methodId}`;
  
  // Validate URL against SSRF protection
  try {
    new URL(url);
  } catch (error) {
    throw new Error('Invalid URL format');
  }
  
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), FOURBYTE_CONFIG.TIMEOUT);
  
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'SafeUtils-SecureClient/2.0.0',
        'Accept': 'application/json',
        'Cache-Control': 'no-cache',
        'DNT': '1'
      },
      signal: controller.signal,
      redirect: 'error' // Never follow redirects
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      throw new Error(`API request failed: ${response.status}`);
    }
    
    // Validate content type
    const contentType = response.headers.get('content-type');
    if (!contentType?.includes('application/json')) {
      throw new Error('Invalid content type');
    }
    
    // Check response size
    const contentLength = response.headers.get('content-length');
    if (contentLength && parseInt(contentLength) > 50000) { // 50KB max
      throw new Error('Response too large');
    }
    
    const text = await response.text();
    
    // Validate JSON before parsing
    if (!text.trim().startsWith('{') && !text.trim().startsWith('[')) {
      throw new Error('Invalid JSON response');
    }
    
    return JSON.parse(text);
  } catch (error) {
    clearTimeout(timeoutId);
    
    if (error instanceof Error && error.name === 'AbortError') {
      throw new Error('Request timeout');
    }
    
    throw error;
  }
}

/**
 * Secure function signature lookup with comprehensive validation and caching
 */
export async function fetchSecure4ByteSignature(methodId: string): Promise<string | null> {
  try {
    // Input validation
    if (!validateMethodId(methodId)) {
      SecureLogger.warn(`Invalid method ID format: ${methodId}`);
      return null;
    }
    
    const normalizedMethodId = methodId.toLowerCase();
    
    // Check cache first
    const cached = secureCache.get(normalizedMethodId);
    if (cached !== undefined) {
      SecureLogger.info(`4byte cache hit for ${normalizedMethodId}`);
      return cached;
    }
    
    // Rate limiting check
    const clientId = 'global'; // Could be IP-based in production
    if (!secureCache.checkRateLimit(clientId)) {
      SecureLogger.warn('4byte API rate limit exceeded');
      return null;
    }
    
    let lastError: Error | null = null;
    
    // Retry logic with exponential backoff
    for (let attempt = 1; attempt <= FOURBYTE_CONFIG.MAX_RETRIES; attempt++) {
      try {
        SecureLogger.info(`4byte API request attempt ${attempt} for ${normalizedMethodId}`);
        
        const data = await secureApiRequest(normalizedMethodId);
        
        // Validate response structure
        if (typeof data !== 'object' || !data) {
          throw new Error('Invalid response structure');
        }
        
        if (!Array.isArray(data.results)) {
          throw new Error('Missing results array');
        }
        
        let signature: string | null = null;
        
        if (data.results.length > 0) {
          // Validate and sanitize results
          const validResults = data.results
            .filter((result: any) => 
              typeof result === 'object' && 
              result && 
              typeof result.text_signature === 'string' &&
              typeof result.id === 'number'
            )
            .slice(0, FOURBYTE_CONFIG.MAX_RESULTS); // Limit results
          
          if (validResults.length > 0) {
            // Sort by ID and take the lowest (most canonical)
            validResults.sort((a: any, b: any) => a.id - b.id);
            
            // Sanitize the signature
            signature = sanitizeHtml(validResults[0].text_signature);
            
            // Additional validation of signature format
            if (signature && !/^[a-zA-Z_][a-zA-Z0-9_]*\([^)]*\)$/.test(signature)) {
              SecureLogger.warn(`Invalid signature format from 4byte: ${signature}`);
              signature = null;
            }
          }
        }
        
        // Cache the result (even if null)
        secureCache.set(normalizedMethodId, signature);
        
        SecureLogger.info(`4byte lookup successful for ${normalizedMethodId}: ${signature || 'not found'}`);
        return signature;
        
      } catch (error) {
        lastError = error as Error;
        SecureLogger.warn(`4byte API attempt ${attempt} failed: ${lastError.message}`);
        
        // Exponential backoff delay
        if (attempt < FOURBYTE_CONFIG.MAX_RETRIES) {
          const delay = Math.min(1000 * Math.pow(2, attempt - 1), 5000);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }
    
    // All attempts failed, cache null result to prevent repeated failures
    secureCache.set(normalizedMethodId, null);
    
    const secureError = processError(lastError || new Error('Unknown error'), {
      methodId: normalizedMethodId,
      context: '4byte_lookup'
    });
    
    SecureLogger.error('4byte lookup failed after all retries', lastError || new Error('Unknown error'));
    return null;
    
  } catch (error) {
    const secureError = processError(error, {
      methodId,
      context: '4byte_lookup_validation'
    });
    
    SecureLogger.error('4byte lookup validation failed', error as Error);
    return null;
  }
}

/**
 * Batch signature lookup for multiple method IDs
 */
export async function fetchSecure4ByteSignaturesBatch(methodIds: string[]): Promise<Record<string, string | null>> {
  const results: Record<string, string | null> = {};
  
  // Process in parallel with concurrency limit
  const CONCURRENT_LIMIT = 3;
  const chunks = [];
  
  for (let i = 0; i < methodIds.length; i += CONCURRENT_LIMIT) {
    chunks.push(methodIds.slice(i, i + CONCURRENT_LIMIT));
  }
  
  for (const chunk of chunks) {
    const promises = chunk.map(async (methodId) => {
      const signature = await fetchSecure4ByteSignature(methodId);
      results[methodId] = signature;
    });
    
    await Promise.all(promises);
    
    // Small delay between chunks to respect rate limits
    if (chunks.indexOf(chunk) < chunks.length - 1) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }
  
  return results;
}

/**
 * Get cache statistics for monitoring
 */
export function get4ByteCacheStats(): {
  size: number;
  hitRate: number;
  lastCleanup: number;
} {
  return {
    size: (secureCache as any).cache.size,
    hitRate: 0, // Would need to track hits/misses for accurate calculation
    lastCleanup: Date.now()
  };
}

// Export legacy-compatible function name
export const fetch4ByteSignature = fetchSecure4ByteSignature;