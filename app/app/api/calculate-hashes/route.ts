/**
 * Secure hash calculation API endpoint
 * Native TypeScript implementation with comprehensive security controls
 */

import { NextRequest, NextResponse } from 'next/server';
import { headers } from 'next/headers';
import { 
  SecureValidator, 
  SSRFProtector, 
  SecureLogger, 
  SecurityError,
  RateLimitError 
} from '@/lib/security';
import { UltraSecureHashCalculator } from '@/lib/secure-hash-calculator';

// Security configuration
const SECURITY_CONFIG = Object.freeze({
  MAX_REQUEST_SIZE: 10000, // 10KB max
  ALLOWED_ORIGINS: [
    'https://safeutils.openzeppelin.com',
    'https://localhost:3000',
    'http://localhost:3000' // Only for development
  ],
  REQUIRED_HEADERS: ['user-agent', 'accept'],
  BLOCKED_USER_AGENTS: [
    'curl', 'wget', 'python', 'go-http-client', 'scanner', 'bot'
  ]
});

/**
 * Comprehensive request validation
 */
async function validateRequest(request: NextRequest): Promise<void> {
  const headersList = headers();
  const validator = SecureValidator.getInstance();

  // Check request size to prevent DoS
  const contentLength = request.headers.get('content-length');
  if (contentLength && parseInt(contentLength) > SECURITY_CONFIG.MAX_REQUEST_SIZE) {
    throw new SecurityError('Request too large', 'REQUEST_TOO_LARGE');
  }

  // Validate origin header (CORS protection)
  const origin = request.headers.get('origin');
  if (origin && !SECURITY_CONFIG.ALLOWED_ORIGINS.includes(origin)) {
    SecureLogger.warn(`Blocked request from unauthorized origin: ${origin}`);
    throw new SecurityError('Unauthorized origin', 'UNAUTHORIZED_ORIGIN');
  }

  // Check for suspicious user agents
  const userAgent = request.headers.get('user-agent') || '';
  const suspiciousUA = SECURITY_CONFIG.BLOCKED_USER_AGENTS.some(blocked => 
    userAgent.toLowerCase().includes(blocked.toLowerCase())
  );
  
  if (suspiciousUA) {
    SecureLogger.warn(`Blocked suspicious user agent: ${userAgent}`);
    throw new SecurityError('Suspicious user agent', 'BLOCKED_USER_AGENT');
  }

  // Rate limiting based on IP
  const forwarded = headersList.get('x-forwarded-for');
  const realIp = headersList.get('x-real-ip');
  const clientIp = forwarded?.split(',')[0] || realIp || 'unknown';
  
  try {
    validator.checkRateLimit(clientIp);
  } catch (error) {
    if (error instanceof RateLimitError) {
      SecureLogger.warn(`Rate limit exceeded for IP: ${clientIp}`);
      throw error;
    }
  }

  // Additional security headers validation
  const referer = request.headers.get('referer');
  if (referer && !SECURITY_CONFIG.ALLOWED_ORIGINS.some(origin => referer.startsWith(origin))) {
    SecureLogger.warn(`Suspicious referer: ${referer}`);
  }
}

/**
 * Secure parameter extraction and validation
 */
function extractSecureParameters(request: NextRequest): {
  network: string;
  address: string;
  nonce: string;
  nestedSafeAddress?: string;
  nestedSafeNonce?: string;
} {
  const validator = SecureValidator.getInstance();
  const { searchParams } = new URL(request.url);

  // Extract and validate required parameters
  const network = validator.validateNetworkName(searchParams.get('network'));
  const address = validator.validateEthereumAddress(searchParams.get('address'));
  const nonce = validator.validateNonce(searchParams.get('nonce')).toString();

  // Extract optional nested Safe parameters
  const nestedSafeAddress = searchParams.get('nestedSafeAddress');
  const nestedSafeNonce = searchParams.get('nestedSafeNonce');

  const result: any = { network, address, nonce };

  if (nestedSafeAddress) {
    result.nestedSafeAddress = validator.validateEthereumAddress(nestedSafeAddress);
  }

  if (nestedSafeNonce) {
    result.nestedSafeNonce = validator.validateNonce(nestedSafeNonce).toString();
  }

  // Validate nested Safe parameters consistency
  if ((nestedSafeAddress && !nestedSafeNonce) || (!nestedSafeAddress && nestedSafeNonce)) {
    throw new SecurityError('Nested Safe parameters must be provided together', 'INVALID_NESTED_PARAMS');
  }

  return result;
}

/**
 * Secure external API call with comprehensive protection
 */
async function secureApiFetch(url: string, options: RequestInit = {}): Promise<Response> {
  const secureOptions: RequestInit = {
    ...options,
    method: options.method || 'GET',
    headers: {
      'User-Agent': 'SafeUtils/1.0.0 (Security-Hardened)',
      'Accept': 'application/json',
      'Accept-Encoding': 'gzip, deflate',
      'Connection': 'keep-alive',
      'Cache-Control': 'no-cache',
      ...options.headers
    },
    timeout: 10000, // 10 second timeout
    signal: AbortSignal.timeout(10000)
  };

  try {
    const response = await fetch(url, secureOptions);
    
    // Validate response size to prevent DoS
    const contentLength = response.headers.get('content-length');
    if (contentLength && parseInt(contentLength) > 1000000) { // 1MB max
      throw new Error('Response too large');
    }

    // Validate content type
    const contentType = response.headers.get('content-type');
    if (!contentType?.includes('application/json')) {
      throw new Error('Invalid content type');
    }

    return response;
  } catch (error) {
    SecureLogger.error(`Secure API fetch failed for ${url}`, error as Error);
    throw new Error('External API request failed');
  }
}

/**
 * Fetch Safe version with security controls
 */
async function fetchSecureSafeVersion(network: string, address: string): Promise<string> {
  const apiUrl = SSRFProtector.validateUrl(network);
  const endpoint = `${apiUrl}/api/v1/safes/${address}/`;

  try {
    const response = await secureApiFetch(endpoint);
    
    if (!response.ok) {
      throw new Error(`Safe contract not found at address ${address} on network ${network}`);
    }
    
    const data = await response.json();
    
    // Validate response structure
    if (typeof data !== 'object' || !data) {
      throw new Error('Invalid API response format');
    }

    const version = typeof data.version === 'string' ? data.version.split('+')[0] : '1.3.0';
    const validator = SecureValidator.getInstance();
    
    return validator.sanitizeString(version, 20);
  } catch (error) {
    SecureLogger.error('Failed to fetch Safe version', error as Error);
    throw new Error('Failed to retrieve Safe version');
  }
}

/**
 * Fetch transaction data with comprehensive security
 */
async function fetchSecureTransactionData(
  network: string, 
  address: string, 
  nonce: string
): Promise<any> {
  const apiUrl = SSRFProtector.validateUrl(network);
  const endpoint = `${apiUrl}/api/v1/safes/${address}/multisig-transactions/?nonce=${nonce}`;

  try {
    const response = await secureApiFetch(endpoint);
    
    if (!response.ok) {
      throw new Error(`API request failed: ${response.statusText}`);
    }
    
    const data = await response.json();
    
    // Validate response structure
    if (typeof data !== 'object' || !data || typeof data.count !== 'number') {
      throw new Error('Invalid API response structure');
    }

    const count = data.count;
    
    if (count === 0) {
      throw new Error('No transaction available for this nonce');
    }

    if (count > 1) {
      SecureLogger.warn(`Multiple transactions detected for nonce ${nonce}`);
    }

    if (!Array.isArray(data.results) || data.results.length === 0) {
      throw new Error('Invalid transaction data format');
    }

    return data.results[0]; // Return first transaction
  } catch (error) {
    SecureLogger.error('Failed to fetch transaction data', error as Error);
    throw new Error('Failed to retrieve transaction data');
  }
}

/**
 * Secure GET endpoint handler
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    // Step 1: Validate request security
    await validateRequest(request);

    // Step 2: Extract and validate parameters
    const { network, address, nonce, nestedSafeAddress, nestedSafeNonce } = 
      extractSecureParameters(request);

    // Step 3: Fetch Safe version with security controls
    const version = await fetchSecureSafeVersion(network, address);

    // Step 4: Fetch transaction data securely
    const txData = await fetchSecureTransactionData(network, address, nonce);

    // Step 5: Initialize ultra-secure hash calculator
    const calculator = UltraSecureHashCalculator.getInstance();

    // Step 6: Get chain ID securely
    const CHAIN_IDS: Record<string, string> = {
      ethereum: '1', arbitrum: '42161', optimism: '10', base: '8453',
      polygon: '137', bsc: '56', avalanche: '43114', celo: '42220',
      gnosis: '100', linea: '59144', zksync: '324', scroll: '534352',
      mantle: '5000', aurora: '1313161554', blast: '81457', worldchain: '10252',
      sepolia: '11155111', 'base-sepolia': '84532', 'gnosis-chiado': '10200',
      hemi: '43111', lens: '232', katana: '747474', 'polygon-zkevm': '1101', xlayer: '204'
    };
    
    const chainId = CHAIN_IDS[network];
    if (!chainId) {
      throw new SecurityError(`Unsupported network: ${network}`, 'UNSUPPORTED_NETWORK');
    }

    // Step 7: Calculate primary hash with military-grade security
    const primaryResult = await calculator.calculateHashes(
      chainId,
      address,
      txData.to || '0x0000000000000000000000000000000000000000',
      txData.value || '0',
      txData.data || '0x',
      txData.operation?.toString() || '0',
      txData.safeTxGas || '0',
      txData.baseGas || '0',
      txData.gasPrice || '0',
      txData.gasToken || '0x0000000000000000000000000000000000000000',
      txData.refundReceiver || '0x0000000000000000000000000000000000000000',
      nonce,
      version
    );

    let nestedResult = null;

    // Step 8: Calculate nested Safe hash if requested
    if (nestedSafeAddress && nestedSafeNonce) {
      const nestedVersion = await fetchSecureSafeVersion(network, nestedSafeAddress);
      
      nestedResult = await calculator.calculateNestedSafeApprovalHash(
        chainId,
        address,
        nestedSafeAddress,
        nestedSafeNonce,
        primaryResult.safeTxHash,
        nestedVersion
      );
    }

    // Step 9: Construct secure response
    const secureResponse = {
      success: true,
      network: {
        name: network,
        chainId: chainId
      },
      transaction: {
        multisigAddress: address,
        to: txData.to || '0x0000000000000000000000000000000000000000',
        nonce: nonce,
        version: version,
        value: txData.value || '0',
        data: txData.data || '0x',
        encodedMessage: primaryResult.encodedMessage,
        dataDecoded: txData.dataDecoded || null
      },
      hashes: {
        domainHash: primaryResult.domainHash,
        messageHash: primaryResult.messageHash,
        safeTxHash: primaryResult.safeTxHash
      },
      nestedSafe: nestedResult ? {
        safeTxHash: nestedResult.safeTxHash,
        domainHash: nestedResult.domainHash,
        messageHash: nestedResult.messageHash,
        encodedMessage: nestedResult.encodedMessage,
        nestedSafeAddress,
        nestedSafeNonce
      } : null,
      timestamp: new Date().toISOString(),
      securityVersion: '2.0.0'
    };

    // Step 10: Return with security headers
    return NextResponse.json(secureResponse, {
      status: 200,
      headers: {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'none'; script-src 'none'",
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      }
    });

  } catch (error) {
    SecureLogger.error('Hash calculation API error', error as Error);

    // Determine appropriate error response
    let status = 500;
    let message = 'Internal server error';

    if (error instanceof SecurityError) {
      status = error.code === 'RATE_LIMIT_EXCEEDED' ? 429 : 400;
      message = 'Security validation failed';
    }

    return NextResponse.json(
      { 
        success: false, 
        error: message,
        timestamp: new Date().toISOString()
      },
      { 
        status,
        headers: {
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          'X-XSS-Protection': '1; mode=block'
        }
      }
    );
  }
}

// Block all other HTTP methods
export async function POST() {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
}

export async function PUT() {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
}

export async function DELETE() {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
}