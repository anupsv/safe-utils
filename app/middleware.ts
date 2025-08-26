/**
 * Security middleware
 * Comprehensive security controls and request filtering
 */

import { NextRequest, NextResponse } from 'next/server';
import { SecureLogger } from './lib/security';

// Security configuration
const SECURITY_CONFIG = Object.freeze({
  // Rate limiting configuration
  RATE_LIMIT_WINDOW: 60 * 1000, // 1 minute
  RATE_LIMIT_MAX_REQUESTS: 30, // Per minute per IP
  BURST_LIMIT: 5, // Burst requests allowed
  
  // Request size limits
  MAX_URL_LENGTH: 2048,
  MAX_HEADER_SIZE: 8192,
  MAX_REQUEST_SIZE: 10 * 1024, // 10KB
  
  // Allowed origins for CORS
  ALLOWED_ORIGINS: [
    'https://safeutils.openzeppelin.com',
    'https://safe-utils-git-main-openzeppelin.vercel.app',
    'https://safe-utils-openzeppelin.vercel.app'
  ],

  // Development origins (only in development)
  DEV_ORIGINS: [
    'http://localhost:3000',
    'https://localhost:3000',
    'http://127.0.0.1:3000'
  ],

  // Blocked user agents (security scanners, bots, etc.)
  BLOCKED_USER_AGENTS: [
    'sqlmap', 'nikto', 'nessus', 'openvas', 'burpsuite',
    'curl', 'wget', 'python-requests', 'go-http-client',
    'scanner', 'crawler', 'bot', 'spider', 'scraper',
    'masscan', 'nmap', 'zap', 'w3af', 'skipfish'
  ],

  // Suspicious headers to block
  SUSPICIOUS_HEADERS: [
    'x-forwarded-host',
    'x-host',
    'x-forwarded-server',
    'x-original-host'
  ],

  // Countries to block (by IP geolocation if available)
  BLOCKED_COUNTRIES: [] as string[], // Can be configured

  // Security headers to set
  SECURITY_HEADERS: {
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), bluetooth=()',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self' https://*.safe.global https://www.4byte.directory; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-site'
  }
});

// In-memory rate limiting store (use Redis in production)
class RateLimiter {
  private requests = new Map<string, { count: number; resetTime: number; burst: number }>();
  private readonly cleanupInterval: NodeJS.Timeout;

  constructor() {
    // Clean up expired entries every minute
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 60000);
  }

  public checkLimit(identifier: string): { allowed: boolean; remaining: number; resetTime: number } {
    const now = Date.now();
    const entry = this.requests.get(identifier);

    if (!entry || now >= entry.resetTime) {
      // New window or expired entry
      const newEntry = {
        count: 1,
        resetTime: now + SECURITY_CONFIG.RATE_LIMIT_WINDOW,
        burst: SECURITY_CONFIG.BURST_LIMIT - 1
      };
      this.requests.set(identifier, newEntry);
      
      return {
        allowed: true,
        remaining: SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS - 1,
        resetTime: newEntry.resetTime
      };
    }

    // Check burst limit first
    if (entry.burst > 0) {
      entry.burst--;
      entry.count++;
      return {
        allowed: true,
        remaining: Math.max(0, SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS - entry.count),
        resetTime: entry.resetTime
      };
    }

    // Check regular limit
    if (entry.count >= SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS) {
      return {
        allowed: false,
        remaining: 0,
        resetTime: entry.resetTime
      };
    }

    entry.count++;
    return {
      allowed: true,
      remaining: Math.max(0, SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS - entry.count),
      resetTime: entry.resetTime
    };
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.requests.entries()) {
      if (now >= entry.resetTime) {
        this.requests.delete(key);
      }
    }
  }

  public destroy(): void {
    clearInterval(this.cleanupInterval);
    this.requests.clear();
  }
}

const rateLimiter = new RateLimiter();

/**
 * Extract client IP with comprehensive header checking
 */
function getClientIP(request: NextRequest): string {
  // Check various headers in order of trustworthiness
  const headers = [
    'cf-connecting-ip', // Cloudflare
    'x-real-ip', // Nginx
    'x-forwarded-for', // Standard proxy header
    'x-client-ip',
    'x-cluster-client-ip',
    'forwarded-for',
    'forwarded'
  ];

  for (const header of headers) {
    const value = request.headers.get(header);
    if (value) {
      // Extract first IP from comma-separated list
      const ip = value.split(',')[0].trim();
      if (isValidIP(ip)) {
        return ip;
      }
    }
  }

  // Fallback to request IP
  return request.ip || 'unknown';
}

/**
 * Validate IP address format
 */
function isValidIP(ip: string): boolean {
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

/**
 * Check for suspicious request patterns
 */
function isSuspiciousRequest(request: NextRequest): string | null {
  const url = request.url;
  const userAgent = request.headers.get('user-agent') || '';
  const method = request.method;

  // Check URL length
  if (url.length > SECURITY_CONFIG.MAX_URL_LENGTH) {
    return 'URL_TOO_LONG';
  }

  // Check for path traversal attempts
  if (url.includes('../') || url.includes('..\\') || url.includes('%2e%2e')) {
    return 'PATH_TRAVERSAL';
  }

  // Check for SQL injection patterns
  const sqlPatterns = [
    'union+select', 'union%20select', 'select+from', 'insert+into',
    'drop+table', 'delete+from', 'update+set', 'exec+xp_'
  ];
  
  if (sqlPatterns.some(pattern => url.toLowerCase().includes(pattern))) {
    return 'SQL_INJECTION';
  }

  // Check for XSS patterns
  const xssPatterns = [
    '<script', 'javascript:', 'vbscript:', 'onload=', 'onerror=',
    'alert(', 'confirm(', 'prompt(', 'eval('
  ];
  
  if (xssPatterns.some(pattern => url.toLowerCase().includes(pattern))) {
    return 'XSS_ATTEMPT';
  }

  // Check for command injection patterns
  const cmdPatterns = [
    ';cat+', ';ls+', ';pwd', ';id', '&&', '||', '|nc+', '|netcat'
  ];
  
  if (cmdPatterns.some(pattern => url.toLowerCase().includes(pattern))) {
    return 'COMMAND_INJECTION';
  }

  // Check blocked user agents
  if (SECURITY_CONFIG.BLOCKED_USER_AGENTS.some(blocked => 
    userAgent.toLowerCase().includes(blocked.toLowerCase())
  )) {
    return 'BLOCKED_USER_AGENT';
  }

  // Check for unusual methods
  const allowedMethods = ['GET', 'POST', 'HEAD', 'OPTIONS'];
  if (!allowedMethods.includes(method)) {
    return 'INVALID_METHOD';
  }

  // Check for suspicious headers
  for (const suspiciousHeader of SECURITY_CONFIG.SUSPICIOUS_HEADERS) {
    if (request.headers.has(suspiciousHeader)) {
      return 'SUSPICIOUS_HEADER';
    }
  }

  return null;
}

/**
 * Validate CORS origin
 */
function isAllowedOrigin(origin: string | null): boolean {
  if (!origin) return true; // No origin header is fine for same-origin

  const isDev = process.env.NODE_ENV === 'development';
  const allowedOrigins = [
    ...SECURITY_CONFIG.ALLOWED_ORIGINS,
    ...(isDev ? SECURITY_CONFIG.DEV_ORIGINS : [])
  ];

  return allowedOrigins.includes(origin);
}

/**
 * Main middleware function
 */
export async function middleware(request: NextRequest): Promise<NextResponse> {
  const startTime = Date.now();
  
  try {
    // Get client IP
    const clientIP = getClientIP(request);
    const userAgent = request.headers.get('user-agent') || 'unknown';
    const method = request.method;
    const url = request.url;

    // Log request for security monitoring
    SecureLogger.info(`${method} ${request.nextUrl.pathname} from ${clientIP}`);

    // Check for suspicious patterns first
    const suspiciousCheck = isSuspiciousRequest(request);
    if (suspiciousCheck) {
      SecureLogger.warn(`Blocked suspicious request: ${suspiciousCheck} from ${clientIP}`);
      
      return new NextResponse('Forbidden', {
        status: 403,
        headers: {
          'Content-Type': 'text/plain',
          ...SECURITY_CONFIG.SECURITY_HEADERS
        }
      });
    }

    // Rate limiting
    const rateLimitResult = rateLimiter.checkLimit(clientIP);
    if (!rateLimitResult.allowed) {
      SecureLogger.warn(`Rate limit exceeded for ${clientIP}`);
      
      return new NextResponse('Too Many Requests', {
        status: 429,
        headers: {
          'Content-Type': 'text/plain',
          'Retry-After': Math.ceil((rateLimitResult.resetTime - Date.now()) / 1000).toString(),
          'X-RateLimit-Limit': SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS.toString(),
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': rateLimitResult.resetTime.toString(),
          ...SECURITY_CONFIG.SECURITY_HEADERS
        }
      });
    }

    // CORS handling
    const origin = request.headers.get('origin');
    if (origin && !isAllowedOrigin(origin)) {
      SecureLogger.warn(`Blocked request from unauthorized origin: ${origin}`);
      
      return new NextResponse('Forbidden', {
        status: 403,
        headers: {
          'Content-Type': 'text/plain',
          ...SECURITY_CONFIG.SECURITY_HEADERS
        }
      });
    }

    // Handle preflight OPTIONS requests
    if (method === 'OPTIONS') {
      return new NextResponse(null, {
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': origin && isAllowedOrigin(origin) ? origin : SECURITY_CONFIG.ALLOWED_ORIGINS[0],
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
          'Access-Control-Max-Age': '86400', // 24 hours
          'Access-Control-Allow-Credentials': 'true',
          ...SECURITY_CONFIG.SECURITY_HEADERS
        }
      });
    }

    // Continue to next middleware/handler
    const response = NextResponse.next();

    // Add security headers to all responses
    Object.entries(SECURITY_CONFIG.SECURITY_HEADERS).forEach(([key, value]) => {
      response.headers.set(key, value);
    });

    // Add CORS headers if needed
    if (origin && isAllowedOrigin(origin)) {
      response.headers.set('Access-Control-Allow-Origin', origin);
      response.headers.set('Access-Control-Allow-Credentials', 'true');
    }

    // Add rate limit headers
    response.headers.set('X-RateLimit-Limit', SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS.toString());
    response.headers.set('X-RateLimit-Remaining', rateLimitResult.remaining.toString());
    response.headers.set('X-RateLimit-Reset', rateLimitResult.resetTime.toString());

    // Add processing time header for monitoring
    const processingTime = Date.now() - startTime;
    response.headers.set('X-Response-Time', `${processingTime}ms`);

    // Add security info header
    response.headers.set('X-Security-Version', '2.0.0');

    return response;

  } catch (error) {
    SecureLogger.error('Middleware error', error as Error);
    
    return new NextResponse('Internal Server Error', {
      status: 500,
      headers: {
        'Content-Type': 'text/plain',
        ...SECURITY_CONFIG.SECURITY_HEADERS
      }
    });
  }
}

/**
 * Configure which routes the middleware applies to
 */
export const config = {
  matcher: [
    // Apply to all API routes
    '/api/:path*',
    
    // Apply to specific pages that need extra security
    '/calculate-hashes/:path*',
    
    // Apply to all routes except static assets
    '/((?!_next/static|_next/image|favicon.ico|robots.txt|sitemap.xml).*)',
  ],
};

// Cleanup on process exit
process.on('SIGINT', () => {
  rateLimiter.destroy();
  process.exit(0);
});

process.on('SIGTERM', () => {
  rateLimiter.destroy();
  process.exit(0);
});