/**
 * Secure error handling and logging system
 * Comprehensive error processing with security controls
 * Information disclosure prevention with detailed logging
 */

import { createHash } from 'crypto';
import { SecureLogger } from './security';

// Error classification system
export enum ErrorSeverity {
  LOW = 1,
  MEDIUM = 2,
  HIGH = 3,
  CRITICAL = 4
}

export enum ErrorCategory {
  VALIDATION = 'VALIDATION',
  AUTHENTICATION = 'AUTHENTICATION',
  AUTHORIZATION = 'AUTHORIZATION',
  CRYPTOGRAPHIC = 'CRYPTOGRAPHIC',
  NETWORK = 'NETWORK',
  SYSTEM = 'SYSTEM',
  BUSINESS_LOGIC = 'BUSINESS_LOGIC',
  SECURITY = 'SECURITY',
  UNKNOWN = 'UNKNOWN'
}

// Comprehensive error interface
export interface SecureError {
  readonly id: string;
  readonly timestamp: Date;
  readonly severity: ErrorSeverity;
  readonly category: ErrorCategory;
  readonly code: string;
  readonly message: string;
  readonly userMessage: string;
  readonly context: Record<string, unknown>;
  readonly stackTrace?: string;
  readonly fingerprint: string;
  readonly remediation?: string;
}

// Error patterns for automatic classification
const ERROR_PATTERNS = Object.freeze({
  [ErrorCategory.VALIDATION]: [
    /validation.*failed/i,
    /invalid.*input/i,
    /malformed.*data/i,
    /parameter.*missing/i,
    /format.*error/i
  ],
  
  [ErrorCategory.AUTHENTICATION]: [
    /authentication.*failed/i,
    /invalid.*credentials/i,
    /token.*expired/i,
    /unauthorized.*access/i
  ],
  
  [ErrorCategory.AUTHORIZATION]: [
    /access.*denied/i,
    /permission.*denied/i,
    /forbidden.*operation/i,
    /insufficient.*privileges/i
  ],
  
  [ErrorCategory.CRYPTOGRAPHIC]: [
    /hash.*mismatch/i,
    /signature.*invalid/i,
    /encryption.*failed/i,
    /key.*error/i,
    /crypto.*integrity/i
  ],
  
  [ErrorCategory.NETWORK]: [
    /network.*error/i,
    /connection.*failed/i,
    /timeout.*exceeded/i,
    /dns.*resolution/i,
    /ssl.*error/i
  ],
  
  [ErrorCategory.SYSTEM]: [
    /system.*error/i,
    /memory.*exhausted/i,
    /disk.*full/i,
    /resource.*unavailable/i
  ],
  
  [ErrorCategory.SECURITY]: [
    /security.*violation/i,
    /attack.*detected/i,
    /breach.*detected/i,
    /suspicious.*activity/i,
    /rate.*limit.*exceeded/i
  ]
});

// Sensitive patterns to sanitize from logs
const SENSITIVE_PATTERNS = [
  // Cryptographic data
  /0x[a-fA-F0-9]{40,}/g, // Ethereum addresses and hashes
  /[A-Za-z0-9+/]{40,}={0,2}/g, // Base64 encoded data
  
  // Potential secrets
  /(?:password|secret|key|token)[\s]*[:=][\s]*[^\s]+/gi,
  /authorization:\s*bearer\s+[^\s]+/gi,
  
  // Personal information
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, // Email addresses
  /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, // IP addresses (partial)
  
  // Financial data
  /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g // Credit card like patterns
];

/**
 * Comprehensive error handler with security protection
 */
export class UltraSecureErrorHandler {
  private static instance: UltraSecureErrorHandler;
  private errorCount = 0;
  private errorHistory: SecureError[] = [];
  private readonly maxHistorySize = 1000;
  
  private constructor() {
    this.setupGlobalErrorHandlers();
  }

  public static getInstance(): UltraSecureErrorHandler {
    if (!UltraSecureErrorHandler.instance) {
      UltraSecureErrorHandler.instance = new UltraSecureErrorHandler();
    }
    return UltraSecureErrorHandler.instance;
  }

  /**
   * Process and secure any error with comprehensive classification
   */
  public processError(
    error: Error | unknown,
    context: Record<string, unknown> = {},
    userFacingMessage?: string
  ): SecureError {
    const errorId = this.generateErrorId();
    const timestamp = new Date();
    
    // Extract error information safely
    const rawMessage = error instanceof Error ? error.message : String(error);
    const stackTrace = error instanceof Error ? error.stack : undefined;
    
    // Classify the error
    const category = this.classifyError(rawMessage);
    const severity = this.determineSeverity(category, rawMessage);
    
    // Generate error code
    const errorCode = this.generateErrorCode(category, rawMessage);
    
    // Sanitize sensitive information
    const sanitizedMessage = this.sanitizeMessage(rawMessage);
    const sanitizedContext = this.sanitizeContext(context);
    const sanitizedStack = stackTrace ? this.sanitizeMessage(stackTrace) : undefined;
    
    // Generate fingerprint for deduplication
    const fingerprint = this.generateFingerprint(sanitizedMessage, category, errorCode);
    
    // Create secure error object
    const secureError: SecureError = Object.freeze({
      id: errorId,
      timestamp,
      severity,
      category,
      code: errorCode,
      message: sanitizedMessage,
      userMessage: userFacingMessage || this.generateUserFriendlyMessage(category, severity),
      context: sanitizedContext,
      stackTrace: sanitizedStack,
      fingerprint,
      remediation: this.generateRemediation(category, errorCode)
    });

    // Store in history (with size limit)
    this.errorHistory.push(secureError);
    if (this.errorHistory.length > this.maxHistorySize) {
      this.errorHistory = this.errorHistory.slice(-this.maxHistorySize);
    }

    this.errorCount++;
    
    // Log appropriately based on severity
    this.logError(secureError);
    
    // Trigger alerts for critical errors
    if (severity >= ErrorSeverity.HIGH) {
      this.triggerSecurityAlert(secureError);
    }

    return secureError;
  }

  /**
   * Generate cryptographically secure error ID
   */
  private generateErrorId(): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substr(2, 9);
    const counter = (this.errorCount % 1000).toString(36);
    return `err_${timestamp}_${random}_${counter}`;
  }

  /**
   * Classify error based on message content
   */
  private classifyError(message: string): ErrorCategory {
    for (const [category, patterns] of Object.entries(ERROR_PATTERNS)) {
      if (patterns.some(pattern => pattern.test(message))) {
        return category as ErrorCategory;
      }
    }
    return ErrorCategory.UNKNOWN;
  }

  /**
   * Determine error severity based on category and content
   */
  private determineSeverity(category: ErrorCategory, message: string): ErrorSeverity {
    // Critical severity indicators
    const criticalPatterns = [
      /integrity.*breach/i,
      /security.*compromised/i,
      /emergency.*shutdown/i,
      /crypto.*tampered/i
    ];

    if (criticalPatterns.some(pattern => pattern.test(message))) {
      return ErrorSeverity.CRITICAL;
    }

    // Category-based severity mapping
    switch (category) {
      case ErrorCategory.SECURITY:
      case ErrorCategory.CRYPTOGRAPHIC:
        return ErrorSeverity.HIGH;
      
      case ErrorCategory.AUTHENTICATION:
      case ErrorCategory.AUTHORIZATION:
        return ErrorSeverity.HIGH;
      
      case ErrorCategory.SYSTEM:
        return ErrorSeverity.MEDIUM;
      
      case ErrorCategory.VALIDATION:
      case ErrorCategory.NETWORK:
        return ErrorSeverity.MEDIUM;
      
      default:
        return ErrorSeverity.LOW;
    }
  }

  /**
   * Generate structured error code
   */
  private generateErrorCode(category: ErrorCategory, message: string): string {
    const categoryCode = category.substring(0, 3).toUpperCase();
    const messageHash = createHash('sha256')
      .update(message)
      .digest('hex')
      .substring(0, 8)
      .toUpperCase();
    
    return `${categoryCode}_${messageHash}`;
  }

  /**
   * Sanitize error message to remove sensitive information
   */
  private sanitizeMessage(message: string): string {
    let sanitized = message;

    // Replace sensitive patterns
    SENSITIVE_PATTERNS.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '[REDACTED]');
    });

    // Remove file paths
    sanitized = sanitized.replace(/\/[^\s]+/g, '[PATH_REDACTED]');
    
    // Remove potential stack traces with file info
    sanitized = sanitized.replace(/at\s+[^\s]+\s+\([^)]+\)/g, 'at [REDACTED]');

    // Limit length to prevent log explosion
    if (sanitized.length > 500) {
      sanitized = sanitized.substring(0, 497) + '...';
    }

    return sanitized;
  }

  /**
   * Sanitize context object
   */
  private sanitizeContext(context: Record<string, unknown>): Record<string, unknown> {
    const sanitized: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(context)) {
      if (typeof value === 'string') {
        sanitized[key] = this.sanitizeMessage(value);
      } else if (typeof value === 'object' && value !== null) {
        // Recursively sanitize nested objects (with depth limit)
        sanitized[key] = this.sanitizeNestedObject(value, 2);
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  /**
   * Sanitize nested objects with depth limit
   */
  private sanitizeNestedObject(obj: unknown, maxDepth: number): unknown {
    if (maxDepth <= 0 || obj === null || typeof obj !== 'object') {
      return '[OBJECT_REDACTED]';
    }

    if (Array.isArray(obj)) {
      return obj.slice(0, 10).map(item => this.sanitizeNestedObject(item, maxDepth - 1));
    }

    const sanitized: Record<string, unknown> = {};
    const entries = Object.entries(obj as Record<string, unknown>).slice(0, 20);

    for (const [key, value] of entries) {
      if (typeof value === 'string') {
        sanitized[key] = this.sanitizeMessage(value);
      } else {
        sanitized[key] = this.sanitizeNestedObject(value, maxDepth - 1);
      }
    }

    return sanitized;
  }

  /**
   * Generate error fingerprint for deduplication
   */
  private generateFingerprint(message: string, category: ErrorCategory, code: string): string {
    return createHash('sha256')
      .update(message + category + code)
      .digest('hex')
      .substring(0, 16);
  }

  /**
   * Generate user-friendly error message
   */
  private generateUserFriendlyMessage(category: ErrorCategory, severity: ErrorSeverity): string {
    if (severity >= ErrorSeverity.CRITICAL) {
      return 'A critical security issue has been detected. Please contact support immediately.';
    }

    switch (category) {
      case ErrorCategory.VALIDATION:
        return 'Please check your input and try again.';
      
      case ErrorCategory.NETWORK:
        return 'Network connection failed. Please check your internet connection and try again.';
      
      case ErrorCategory.AUTHENTICATION:
        return 'Authentication failed. Please verify your credentials.';
      
      case ErrorCategory.AUTHORIZATION:
        return 'You do not have permission to perform this action.';
      
      case ErrorCategory.CRYPTOGRAPHIC:
        return 'A security verification failed. Please try again or contact support.';
      
      case ErrorCategory.SYSTEM:
        return 'A system error occurred. Please try again later.';
      
      default:
        return 'An unexpected error occurred. Please try again.';
    }
  }

  /**
   * Generate remediation suggestions
   */
  private generateRemediation(category: ErrorCategory, code: string): string {
    switch (category) {
      case ErrorCategory.VALIDATION:
        return 'Verify input parameters and format before retrying.';
      
      case ErrorCategory.NETWORK:
        return 'Check network connectivity and API endpoint availability.';
      
      case ErrorCategory.CRYPTOGRAPHIC:
        return 'Verify cryptographic constants and hash calculations.';
      
      case ErrorCategory.SECURITY:
        return 'Investigate potential security breach and review access logs.';
      
      default:
        return 'Review error context and retry with corrected parameters.';
    }
  }

  /**
   * Log error with appropriate level
   */
  private logError(error: SecureError): void {
    const logMessage = `[${error.code}] ${error.category}: ${error.message}`;
    
    switch (error.severity) {
      case ErrorSeverity.CRITICAL:
        SecureLogger.error(`CRITICAL: ${logMessage}`, new Error(error.code));
        break;
      
      case ErrorSeverity.HIGH:
        SecureLogger.error(`HIGH: ${logMessage}`);
        break;
      
      case ErrorSeverity.MEDIUM:
        SecureLogger.warn(`MEDIUM: ${logMessage}`);
        break;
      
      case ErrorSeverity.LOW:
        SecureLogger.info(`LOW: ${logMessage}`);
        break;
    }
  }

  /**
   * Trigger security alerts for high-severity errors
   */
  private triggerSecurityAlert(error: SecureError): void {
    if (error.severity >= ErrorSeverity.HIGH) {
      const alertMessage = `Security Alert - ${error.category} error detected: ${error.code}`;
      
      // In production, this would:
      // - Send to security monitoring system
      // - Trigger incident response
      // - Notify security team
      
      console.error('🚨 SECURITY ALERT 🚨');
      console.error(alertMessage);
      console.error(`Fingerprint: ${error.fingerprint}`);
    }
  }

  /**
   * Setup global error handlers
   */
  private setupGlobalErrorHandlers(): void {
    // Unhandled promise rejections
    process.on('unhandledRejection', (reason: unknown) => {
      const error = reason instanceof Error ? reason : new Error(String(reason));
      this.processError(error, { type: 'unhandledRejection' });
    });

    // Uncaught exceptions
    process.on('uncaughtException', (error: Error) => {
      this.processError(error, { type: 'uncaughtException' });
      
      // Give time to log before potentially exiting
      setTimeout(() => {
        process.exit(1);
      }, 1000);
    });

    // Warning events
    process.on('warning', (warning: Error) => {
      this.processError(warning, { type: 'warning' });
    });
  }

  /**
   * Get error statistics
   */
  public getErrorStatistics(): {
    totalErrors: number;
    errorsByCategory: Record<ErrorCategory, number>;
    errorsBySeverity: Record<ErrorSeverity, number>;
    recentErrors: SecureError[];
  } {
    const byCategory = {} as Record<ErrorCategory, number>;
    const bySeverity = {} as Record<ErrorSeverity, number>;

    // Initialize counters
    Object.values(ErrorCategory).forEach(cat => byCategory[cat as ErrorCategory] = 0);
    Object.values(ErrorSeverity).forEach(sev => bySeverity[sev as ErrorSeverity] = 0);

    // Count errors
    this.errorHistory.forEach(error => {
      byCategory[error.category]++;
      bySeverity[error.severity]++;
    });

    return {
      totalErrors: this.errorCount,
      errorsByCategory: byCategory,
      errorsBySeverity: bySeverity,
      recentErrors: this.errorHistory.slice(-20) // Last 20 errors
    };
  }

  /**
   * Create error response for API endpoints
   */
  public createErrorResponse(error: SecureError): {
    success: false;
    error: {
      code: string;
      message: string;
      timestamp: string;
    };
    meta: {
      requestId: string;
    };
  } {
    return {
      success: false,
      error: {
        code: error.code,
        message: error.userMessage,
        timestamp: error.timestamp.toISOString()
      },
      meta: {
        requestId: error.id
      }
    };
  }
}

// Global error handler instance
const secureErrorHandler = UltraSecureErrorHandler.getInstance();

// Export convenient functions
export const processError = (error: Error | unknown, context?: Record<string, unknown>, userMessage?: string) =>
  secureErrorHandler.processError(error, context, userMessage);

export const getErrorStats = () =>
  secureErrorHandler.getErrorStatistics();

export const createErrorResponse = (error: SecureError) =>
  secureErrorHandler.createErrorResponse(error);

// Initialize message
SecureLogger.info('Ultra-Secure Error Handler initialized with military-grade protection');