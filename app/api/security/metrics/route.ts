/**
 * Security metrics API endpoint
 * Provides real-time security monitoring data
 */

import { NextRequest, NextResponse } from 'next/server';
import { SecureLogger, processError, SecurityError } from '@/lib/security';
import { sanitizeHtml } from '@/lib/secure-output';

interface SecurityMetrics {
  timestamp: string;
  csrfAttemptsBlocked: number;
  rateLimitViolations: number;
  sriVerifications: {
    successful: number;
    failed: number;
    total: number;
  };
  cspViolations: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  inputValidationFailures: number;
  authenticationAttempts: {
    successful: number;
    failed: number;
  };
  suspiciousActivities: string[];
  systemStatus: 'secure' | 'warning' | 'critical';
}

// In-memory metrics storage (in production, use Redis or database)
class SecurityMetricsCollector {
  private static instance: SecurityMetricsCollector;
  private metrics: SecurityMetrics = {
    timestamp: new Date().toISOString(),
    csrfAttemptsBlocked: 0,
    rateLimitViolations: 0,
    sriVerifications: {
      successful: 0,
      failed: 0,
      total: 0
    },
    cspViolations: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    },
    inputValidationFailures: 0,
    authenticationAttempts: {
      successful: 0,
      failed: 0
    },
    suspiciousActivities: [],
    systemStatus: 'secure'
  };

  private recentEvents: Array<{
    type: string;
    timestamp: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    details: any;
  }> = [];

  public static getInstance(): SecurityMetricsCollector {
    if (!SecurityMetricsCollector.instance) {
      SecurityMetricsCollector.instance = new SecurityMetricsCollector();
    }
    return SecurityMetricsCollector.instance;
  }

  public recordEvent(type: string, severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL', details: any = {}): void {
    try {
      this.recentEvents.push({
        type: sanitizeHtml(type),
        timestamp: new Date().toISOString(),
        severity,
        details: this.sanitizeEventDetails(details)
      });

      // Keep only last 1000 events
      if (this.recentEvents.length > 1000) {
        this.recentEvents.shift();
      }

      this.updateMetrics(type, severity, details);
      this.updateSystemStatus();

      SecureLogger.info(`Security event recorded: ${type} (${severity})`);
    } catch (error) {
      SecureLogger.error('Failed to record security event', error as Error);
    }
  }

  private sanitizeEventDetails(details: any): any {
    if (typeof details !== 'object' || !details) return {};

    const sanitized: any = {};
    for (const [key, value] of Object.entries(details)) {
      if (typeof value === 'string') {
        sanitized[key] = sanitizeHtml(value.substring(0, 200));
      } else if (typeof value === 'number') {
        sanitized[key] = value;
      } else if (typeof value === 'boolean') {
        sanitized[key] = value;
      }
    }
    return sanitized;
  }

  private updateMetrics(type: string, severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL', details: any): void {
    this.metrics.timestamp = new Date().toISOString();

    switch (type) {
      case 'csrf_blocked':
        this.metrics.csrfAttemptsBlocked++;
        break;
      case 'rate_limit_violation':
        this.metrics.rateLimitViolations++;
        break;
      case 'sri_verification_success':
        this.metrics.sriVerifications.successful++;
        this.metrics.sriVerifications.total++;
        break;
      case 'sri_verification_failure':
        this.metrics.sriVerifications.failed++;
        this.metrics.sriVerifications.total++;
        break;
      case 'csp_violation':
        switch (severity) {
          case 'CRITICAL':
            this.metrics.cspViolations.critical++;
            break;
          case 'HIGH':
            this.metrics.cspViolations.high++;
            break;
          case 'MEDIUM':
            this.metrics.cspViolations.medium++;
            break;
          case 'LOW':
            this.metrics.cspViolations.low++;
            break;
        }
        break;
      case 'input_validation_failure':
        this.metrics.inputValidationFailures++;
        break;
      case 'auth_success':
        this.metrics.authenticationAttempts.successful++;
        break;
      case 'auth_failure':
        this.metrics.authenticationAttempts.failed++;
        break;
      case 'suspicious_activity':
        const activity = details.description || `${type} detected`;
        this.metrics.suspiciousActivities.unshift(sanitizeHtml(activity));
        // Keep only last 10 activities
        if (this.metrics.suspiciousActivities.length > 10) {
          this.metrics.suspiciousActivities.pop();
        }
        break;
    }
  }

  private updateSystemStatus(): void {
    const criticalEvents = this.recentEvents.filter(e => 
      e.severity === 'CRITICAL' && 
      Date.now() - new Date(e.timestamp).getTime() < 300000 // Last 5 minutes
    ).length;

    const highEvents = this.recentEvents.filter(e => 
      e.severity === 'HIGH' && 
      Date.now() - new Date(e.timestamp).getTime() < 300000
    ).length;

    if (criticalEvents > 0) {
      this.metrics.systemStatus = 'critical';
    } else if (highEvents > 5 || this.metrics.rateLimitViolations > 50) {
      this.metrics.systemStatus = 'warning';
    } else {
      this.metrics.systemStatus = 'secure';
    }
  }

  public getMetrics(): SecurityMetrics {
    return { ...this.metrics };
  }

  public getRecentEvents(limit: number = 50): Array<{
    type: string;
    timestamp: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    details: any;
  }> {
    return this.recentEvents.slice(-limit);
  }

  public resetMetrics(): void {
    this.metrics = {
      timestamp: new Date().toISOString(),
      csrfAttemptsBlocked: 0,
      rateLimitViolations: 0,
      sriVerifications: {
        successful: 0,
        failed: 0,
        total: 0
      },
      cspViolations: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      },
      inputValidationFailures: 0,
      authenticationAttempts: {
        successful: 0,
        failed: 0
      },
      suspiciousActivities: [],
      systemStatus: 'secure'
    };
    this.recentEvents = [];
    SecureLogger.info('Security metrics reset');
  }
}

const metricsCollector = SecurityMetricsCollector.getInstance();

// Simulate some activity for demonstration
setInterval(() => {
  // Simulate random security events for demo purposes
  const eventTypes = [
    { type: 'sri_verification_success', severity: 'LOW' as const },
    { type: 'auth_success', severity: 'LOW' as const },
    { type: 'input_validation_failure', severity: 'MEDIUM' as const },
  ];
  
  const randomEvent = eventTypes[Math.floor(Math.random() * eventTypes.length)];
  metricsCollector.recordEvent(randomEvent.type, randomEvent.severity, {
    source: 'automated_simulation',
    timestamp: new Date().toISOString()
  });
}, 30000); // Every 30 seconds

export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    // Basic rate limiting for metrics endpoint
    const clientIp = request.ip || 
      request.headers.get('x-forwarded-for')?.split(',')[0] ||
      request.headers.get('x-real-ip') ||
      'unknown';

    // Get current metrics
    const metrics = metricsCollector.getMetrics();

    SecureLogger.info(`Security metrics requested by ${clientIp.substring(0, 10)}...`);

    return NextResponse.json(
      metrics,
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache',
          'Expires': '0',
          'X-Security-Metrics': 'enabled'
        }
      }
    );

  } catch (error) {
    const secureError = processError(error, {
      endpoint: 'security-metrics',
      clientIp: request.ip?.substring(0, 10) + '...'
    });

    SecureLogger.error('Security metrics endpoint failed', error as Error);

    return NextResponse.json(
      { 
        error: 'Failed to retrieve security metrics',
        timestamp: new Date().toISOString()
      },
      { status: 500 }
    );
  }
}

// Administrative endpoint to record security events
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    // Validate content type
    const contentType = request.headers.get('content-type');
    if (!contentType?.includes('application/json')) {
      throw new SecurityError('Invalid content type', 'INVALID_CONTENT_TYPE');
    }

    // Parse request body
    const body = await request.json();
    
    if (!body.type || !body.severity) {
      throw new SecurityError('Missing required fields: type, severity', 'MISSING_FIELDS');
    }

    // Validate severity
    const validSeverities: Array<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'> = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    if (!validSeverities.includes(body.severity)) {
      throw new SecurityError('Invalid severity level', 'INVALID_SEVERITY');
    }

    // Record the event
    metricsCollector.recordEvent(
      body.type,
      body.severity,
      body.details || {}
    );

    return NextResponse.json(
      { 
        status: 'recorded',
        timestamp: new Date().toISOString()
      },
      { status: 201 }
    );

  } catch (error) {
    const secureError = processError(error, {
      endpoint: 'security-metrics-record'
    });

    SecureLogger.error('Security metrics recording failed', error as Error);

    return NextResponse.json(
      { error: 'Failed to record security event' },
      { status: 400 }
    );
  }
}

// Export the metrics collector for use by other modules
export { metricsCollector as SecurityMetricsCollector };