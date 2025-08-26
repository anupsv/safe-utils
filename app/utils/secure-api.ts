/**
 * Secure API utilities
 * Protected API calls with SSRF protection and comprehensive validation
 */

import { 
  SecureValidator, 
  SSRFProtector, 
  SecureLogger, 
  SecurityError,
  InputValidationError 
} from '@/lib/security';
import { TransactionParams } from '@/types/form-types';

// Network configuration with strict validation
const SECURE_NETWORKS = Object.freeze([
  { value: 'ethereum', apiDomain: 'safe-transaction-mainnet.safe.global' },
  { value: 'arbitrum', apiDomain: 'safe-transaction-arbitrum.safe.global' },
  { value: 'optimism', apiDomain: 'safe-transaction-optimism.safe.global' },
  { value: 'base', apiDomain: 'safe-transaction-base.safe.global' },
  { value: 'polygon', apiDomain: 'safe-transaction-polygon.safe.global' },
  { value: 'bsc', apiDomain: 'safe-transaction-bsc.safe.global' },
  { value: 'avalanche', apiDomain: 'safe-transaction-avalanche.safe.global' },
  { value: 'celo', apiDomain: 'safe-transaction-celo.safe.global' },
  { value: 'gnosis', apiDomain: 'safe-transaction-gnosis-chain.safe.global' },
  { value: 'linea', apiDomain: 'safe-transaction-linea.safe.global' },
  { value: 'zksync', apiDomain: 'safe-transaction-zksync.safe.global' },
  { value: 'scroll', apiDomain: 'safe-transaction-scroll.safe.global' },
  { value: 'mantle', apiDomain: 'safe-transaction-mantle.safe.global' },
  { value: 'aurora', apiDomain: 'safe-transaction-aurora.safe.global' },
  { value: 'blast', apiDomain: 'safe-transaction-blast.safe.global' },
  { value: 'worldchain', apiDomain: 'safe-transaction-worldchain.safe.global' },
  { value: 'sepolia', apiDomain: 'safe-transaction-sepolia.safe.global' },
  { value: 'base-sepolia', apiDomain: 'safe-transaction-base-sepolia.safe.global' },
  { value: 'gnosis-chiado', apiDomain: 'safe-transaction-chiado.safe.global' },
  { value: 'hemi', apiDomain: 'safe-transaction-hemi.safe.global' },
  { value: 'lens', apiDomain: 'safe-transaction-lens.safe.global' },
  { value: 'katana', apiDomain: 'safe-transaction-katana.safe.global' },
  { value: 'polygon-zkevm', apiDomain: 'safe-transaction-zkevm.safe.global' },
  { value: 'xlayer', apiDomain: 'safe-transaction-xlayer.safe.global' }
]);

/**
 * Secure HTTP client with comprehensive protection
 */
class SecureHttpClient {
  private static instance: SecureHttpClient;
  private requestCount = 0;
  private readonly maxRequests = 100; // Per instance limit
  
  private constructor() {}

  public static getInstance(): SecureHttpClient {
    if (!SecureHttpClient.instance) {
      SecureHttpClient.instance = new SecureHttpClient();
    }
    return SecureHttpClient.instance;
  }

  /**
   * Secure fetch with comprehensive validation
   */
  public async secureFetch(url: string, options: RequestInit = {}): Promise<Response> {
    // Request count limiting
    if (++this.requestCount > this.maxRequests) {
      throw new SecurityError('Request limit exceeded for this instance', 'REQUEST_LIMIT');
    }

    // URL validation
    this.validateUrl(url);

    const secureOptions: RequestInit = {
      ...options,
      method: options.method || 'GET',
      headers: {
        'User-Agent': 'SafeUtils-SecureClient/2.0.0',
        'Accept': 'application/json',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close', // Prevent connection reuse
        'Cache-Control': 'no-cache',
        'DNT': '1',
        ...options.headers
      },
      timeout: 8000, // 8 second timeout
      signal: AbortSignal.timeout(8000),
      redirect: 'error', // Never follow redirects
      referrerPolicy: 'no-referrer'
    };

    try {
      const response = await fetch(url, secureOptions);
      
      // Comprehensive response validation
      await this.validateResponse(response);
      
      return response;
    } catch (error) {
      SecureLogger.error(`Secure fetch failed for ${this.sanitizeUrl(url)}`, error as Error);
      throw new SecurityError('Secure HTTP request failed', 'HTTP_REQUEST_FAILED');
    }
  }

  /**
   * Validate URL for SSRF protection
   */
  private validateUrl(url: string): void {
    try {
      const parsed = new URL(url);
      
      // Protocol validation
      if (parsed.protocol !== 'https:') {
        throw new SecurityError('Only HTTPS URLs are allowed', 'INVALID_PROTOCOL');
      }

      // Domain validation
      const allowedDomains = [
        ...SECURE_NETWORKS.map(n => n.apiDomain),
        'www.4byte.directory'
      ];

      if (!allowedDomains.includes(parsed.hostname)) {
        throw new SecurityError(`Domain not in allowlist: ${parsed.hostname}`, 'DOMAIN_NOT_ALLOWED');
      }

      // Path validation - prevent traversal
      if (parsed.pathname.includes('..') || parsed.pathname.includes('//')) {
        throw new SecurityError('Invalid path detected', 'INVALID_PATH');
      }

      // Port validation
      if (parsed.port && parsed.port !== '443') {
        throw new SecurityError('Invalid port', 'INVALID_PORT');
      }

    } catch (error) {
      if (error instanceof SecurityError) throw error;
      throw new SecurityError('URL validation failed', 'URL_VALIDATION_FAILED');
    }
  }

  /**
   * Validate HTTP response
   */
  private async validateResponse(response: Response): Promise<void> {
    // Status code validation
    if (!response.ok && response.status !== 404) {
      throw new SecurityError(`HTTP error: ${response.status}`, 'HTTP_ERROR');
    }

    // Content length validation
    const contentLength = response.headers.get('content-length');
    if (contentLength && parseInt(contentLength) > 2000000) { // 2MB max
      throw new SecurityError('Response too large', 'RESPONSE_TOO_LARGE');
    }

    // Content type validation
    const contentType = response.headers.get('content-type');
    if (contentType && !contentType.includes('application/json')) {
      SecureLogger.warn(`Unexpected content type: ${contentType}`);
    }

    // Security headers validation
    const securityHeaders = ['x-frame-options', 'x-content-type-options'];
    securityHeaders.forEach(header => {
      if (!response.headers.get(header)) {
        SecureLogger.warn(`Missing security header: ${header}`);
      }
    });
  }

  /**
   * Sanitize URL for logging
   */
  private sanitizeUrl(url: string): string {
    try {
      const parsed = new URL(url);
      return `${parsed.protocol}//${parsed.hostname}${parsed.pathname.substring(0, 50)}...`;
    } catch {
      return '[INVALID_URL]';
    }
  }
}

/**
 * Secure Safe version fetcher
 */
export async function fetchSecureSafeVersion(network: string, address: string): Promise<string> {
  const validator = SecureValidator.getInstance();
  const httpClient = SecureHttpClient.getInstance();

  // Validate inputs with extreme security
  const cleanNetwork = validator.validateNetworkName(network);
  const cleanAddress = validator.validateEthereumAddress(address);

  // Get secure API URL
  const apiUrl = SSRFProtector.validateUrl(cleanNetwork);
  const endpoint = `${apiUrl}/api/v1/safes/${cleanAddress}/`;

  try {
    const response = await httpClient.secureFetch(endpoint);
    
    if (response.status === 404) {
      throw new SecurityError(`Safe not found: ${cleanAddress}`, 'SAFE_NOT_FOUND');
    }

    if (!response.ok) {
      throw new SecurityError(`API error: ${response.status}`, 'API_ERROR');
    }
    
    const data = await response.json();
    
    // Ultra-strict response validation
    if (typeof data !== 'object' || !data) {
      throw new SecurityError('Invalid API response format', 'INVALID_RESPONSE');
    }

    if (typeof data.version !== 'string') {
      SecureLogger.warn('Missing version in API response, using default');
      return '1.3.0';
    }

    // Clean and validate version string
    const version = data.version.split('+')[0]; // Remove build metadata
    const cleanVersion = validator.sanitizeString(version, 20);
    
    if (!/^\d+\.\d+\.\d+$/.test(cleanVersion)) {
      throw new SecurityError('Invalid version format', 'INVALID_VERSION');
    }

    SecureLogger.info(`Successfully fetched Safe version: ${cleanVersion}`);
    return cleanVersion;

  } catch (error) {
    if (error instanceof SecurityError) throw error;
    SecureLogger.error('Safe version fetch failed', error as Error);
    throw new SecurityError('Failed to fetch Safe version', 'VERSION_FETCH_FAILED');
  }
}

/**
 * Secure transaction data fetcher with comprehensive validation
 */
export async function fetchSecureTransactionDataFromApi(
  network: string,
  address: string,
  nonce: string
): Promise<TransactionParams> {
  const validator = SecureValidator.getInstance();
  const httpClient = SecureHttpClient.getInstance();

  // Ultra-strict input validation
  const cleanNetwork = validator.validateNetworkName(network);
  const cleanAddress = validator.validateEthereumAddress(address);
  const cleanNonce = validator.validateNonce(nonce).toString();

  // Get secure API URL with SSRF protection
  const apiUrl = SSRFProtector.validateUrl(cleanNetwork);
  const endpoint = `${apiUrl}/api/v1/safes/${cleanAddress}/multisig-transactions/?nonce=${cleanNonce}`;

  try {
    const response = await httpClient.secureFetch(endpoint);
    
    if (!response.ok) {
      throw new SecurityError(`API request failed: ${response.status}`, 'API_REQUEST_FAILED');
    }
    
    const data = await response.json();
    
    // Comprehensive response structure validation
    if (typeof data !== 'object' || !data) {
      throw new SecurityError('Invalid API response structure', 'INVALID_RESPONSE_STRUCTURE');
    }

    if (typeof data.count !== 'number') {
      throw new SecurityError('Missing count field in response', 'MISSING_COUNT');
    }

    const count = data.count;
    
    if (count === 0) {
      throw new SecurityError('No transaction available for this nonce', 'NO_TRANSACTION');
    }

    if (count > 10) {
      throw new SecurityError('Too many transactions for single nonce', 'TOO_MANY_TRANSACTIONS');
    }

    if (!Array.isArray(data.results) || data.results.length === 0) {
      throw new SecurityError('Invalid transaction results format', 'INVALID_RESULTS');
    }

    const txData = data.results[0];

    // Validate transaction data structure
    if (typeof txData !== 'object' || !txData) {
      throw new SecurityError('Invalid transaction data', 'INVALID_TX_DATA');
    }

    // Fetch Safe version securely
    const version = await fetchSecureSafeVersion(cleanNetwork, cleanAddress);

    // Validate and sanitize all transaction parameters
    const secureParams: TransactionParams = {
      to: validator.validateEthereumAddress(txData.to || '0x0000000000000000000000000000000000000000'),
      value: validator.sanitizeString(txData.value?.toString() || '0', 100),
      data: validator.validateHexData(txData.data || '0x'),
      operation: validator.sanitizeString(txData.operation?.toString() || '0', 2),
      safeTxGas: validator.sanitizeString(txData.safeTxGas?.toString() || '0', 100),
      baseGas: validator.sanitizeString(txData.baseGas?.toString() || '0', 100),
      gasPrice: validator.sanitizeString(txData.gasPrice?.toString() || '0', 100),
      gasToken: validator.validateEthereumAddress(txData.gasToken || '0x0000000000000000000000000000000000000000'),
      refundReceiver: validator.validateEthereumAddress(txData.refundReceiver || '0x0000000000000000000000000000000000000000'),
      nonce: cleanNonce,
      version: version,
      dataDecoded: this.sanitizeDataDecoded(txData.dataDecoded)
    };

    // Additional security validation
    this.validateTransactionSecurity(secureParams);

    SecureLogger.info(`Successfully fetched transaction data for nonce ${cleanNonce}`);
    return secureParams;

  } catch (error) {
    if (error instanceof SecurityError) throw error;
    SecureLogger.error('Transaction data fetch failed', error as Error);
    throw new SecurityError('Failed to fetch transaction data', 'TX_FETCH_FAILED');
  }
}

/**
 * Sanitize decoded transaction data
 */
function sanitizeDataDecoded(dataDecoded: any): any {
  if (!dataDecoded || typeof dataDecoded !== 'object') {
    return null;
  }

  const validator = SecureValidator.getInstance();

  try {
    return {
      method: typeof dataDecoded.method === 'string' 
        ? validator.sanitizeString(dataDecoded.method, 100) 
        : 'Unknown',
      parameters: Array.isArray(dataDecoded.parameters) 
        ? dataDecoded.parameters.slice(0, 20) // Limit parameters
        : []
    };
  } catch (error) {
    SecureLogger.warn('Failed to sanitize decoded data');
    return null;
  }
}

/**
 * Validate transaction for security risks
 */
function validateTransactionSecurity(params: TransactionParams): void {
  const validator = SecureValidator.getInstance();

  // Check for suspicious patterns
  if (params.operation === '1') {
    SecureLogger.warn(`Delegatecall operation detected to ${params.to}`);
  }

  // Validate numeric parameters for overflow
  const numericFields = ['value', 'safeTxGas', 'baseGas', 'gasPrice'];
  numericFields.forEach(field => {
    const value = (params as any)[field];
    if (value && !/^\d+$/.test(value)) {
      throw new SecurityError(`Invalid numeric value for ${field}`, 'INVALID_NUMERIC');
    }
  });

  // Check data size
  if (params.data.length > 200000) { // 100KB hex = ~200K chars
    throw new SecurityError('Transaction data too large', 'DATA_TOO_LARGE');
  }

  // Gas token validation
  if (params.gasToken !== '0x0000000000000000000000000000000000000000') {
    SecureLogger.warn('Custom gas token detected - potential gas manipulation');
  }

  // Refund receiver validation
  if (params.refundReceiver !== '0x0000000000000000000000000000000000000000') {
    SecureLogger.warn('Custom refund receiver detected - potential fund redirection');
  }
}

/**
 * Generate secure share URL with validation
 */
export function generateSecureShareUrl(network: string, address: string, nonce: string): string {
  const validator = SecureValidator.getInstance();
  
  // Validate all inputs
  const cleanNetwork = validator.validateNetworkName(network);
  const cleanAddress = validator.validateEthereumAddress(address);
  const cleanNonce = validator.validateNonce(nonce).toString();

  // Get network prefix securely
  const networkConfig = SECURE_NETWORKS.find(n => n.value === cleanNetwork);
  if (!networkConfig) {
    throw new SecurityError(`Network not found: ${cleanNetwork}`, 'NETWORK_NOT_FOUND');
  }

  // Construct secure URL
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || 'https://safeutils.openzeppelin.com';
  const safeAddress = `${cleanNetwork}:${cleanAddress}`;
  
  try {
    const url = new URL(baseUrl);
    url.searchParams.set('safeAddress', safeAddress);
    url.searchParams.set('nonce', cleanNonce);
    
    return url.toString();
  } catch (error) {
    throw new SecurityError('Failed to generate secure URL', 'URL_GENERATION_FAILED');
  }
}

/**
 * Clean up resources and reset state
 */
export function cleanupSecureApi(): void {
  const validator = SecureValidator.getInstance();
  validator.cleanupRateLimits();
  
  // Reset HTTP client instance
  (SecureHttpClient as any).instance = null;
  
  SecureLogger.info('Secure API cleanup completed');
}