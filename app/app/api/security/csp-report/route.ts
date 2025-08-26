/**
 * Content Security Policy violation reporting endpoint
 * Collects and analyzes CSP violations for security monitoring
 */

import { NextRequest, NextResponse } from 'next/server';
import { SecureLogger, SecurityError } from '@/lib/security';
import { processError } from '@/lib/secure-error-handler';
import { sanitizeHtml } from '@/lib/secure-output';

interface CSPViolationReport {
  'csp-report': {
    'document-uri': string;
    'referrer': string;
    'violated-directive': string;
    'effective-directive': string;
    'original-policy': string;
    'blocked-uri': string;
    'line-number': number;
    'column-number': number;
    'source-file': string;
    'status-code': number;
    'script-sample': string;
  };
}

// Rate limiting for CSP reports to prevent spam
const reportLimiter = new Map<string, { count: number; resetTime: number }>();
const MAX_REPORTS_PER_IP = 100; // per hour
const RATE_LIMIT_WINDOW = 60 * 60 * 1000; // 1 hour

function checkReportRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = reportLimiter.get(ip);

  if (!entry || now >= entry.resetTime) {
    reportLimiter.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return true;
  }

  if (entry.count >= MAX_REPORTS_PER_IP) {
    return false;
  }

  entry.count++;
  return true;
}

function analyzeCSPViolation(report: CSPViolationReport['csp-report']): {
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  threatType: string;
  actionRequired: boolean;
} {
  const blockedUri = report['blocked-uri'] || '';
  const violatedDirective = report['violated-directive'] || '';
  const scriptSample = report['script-sample'] || '';

  // Critical violations - potential XSS attacks
  if (
    violatedDirective.includes('script-src') &&
    (blockedUri.includes('data:') || 
     blockedUri.includes('javascript:') ||
     scriptSample.includes('eval(') ||
     scriptSample.includes('Function('))
  ) {
    return {
      severity: 'CRITICAL',
      threatType: 'XSS_ATTEMPT',
      actionRequired: true
    };
  }

  // High severity - unsafe inline attempts
  if (
    violatedDirective.includes('script-src') &&
    blockedUri.includes('unsafe-inline')
  ) {
    return {
      severity: 'HIGH',
      threatType: 'UNSAFE_INLINE_SCRIPT',
      actionRequired: true
    };
  }

  // Medium severity - external resource loading
  if (
    violatedDirective.includes('img-src') ||
    violatedDirective.includes('font-src') ||
    violatedDirective.includes('style-src')
  ) {
    return {
      severity: 'MEDIUM',
      threatType: 'EXTERNAL_RESOURCE',
      actionRequired: false
    };
  }

  // Low severity - other violations
  return {
    severity: 'LOW',
    threatType: 'POLICY_VIOLATION',
    actionRequired: false
  };
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    // Rate limiting by IP
    const clientIp = request.ip || 
      request.headers.get('x-forwarded-for')?.split(',')[0] ||
      request.headers.get('x-real-ip') ||
      'unknown';

    if (!checkReportRateLimit(clientIp)) {
      SecureLogger.warn(`CSP report rate limit exceeded for IP: ${clientIp}`);
      return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
    }

    // Validate content type
    const contentType = request.headers.get('content-type');
    if (!contentType?.includes('application/csp-report') && 
        !contentType?.includes('application/json')) {
      throw new SecurityError('Invalid content type for CSP report', 'INVALID_CONTENT_TYPE');
    }

    // Parse and validate request body
    let reportData: CSPViolationReport;
    
    try {
      const rawBody = await request.text();
      
      // Limit report size to prevent DoS
      if (rawBody.length > 10000) { // 10KB max
        throw new SecurityError('CSP report too large', 'REPORT_TOO_LARGE');
      }

      reportData = JSON.parse(rawBody);
    } catch (error) {
      throw new SecurityError('Invalid CSP report format', 'INVALID_FORMAT');
    }

    // Validate report structure
    if (!reportData['csp-report'] || typeof reportData['csp-report'] !== 'object') {
      throw new SecurityError('Missing csp-report field', 'MISSING_CSP_REPORT');
    }

    const report = reportData['csp-report'];

    // Sanitize report data
    const sanitizedReport = {
      documentUri: sanitizeHtml(report['document-uri'] || ''),
      referrer: sanitizeHtml(report['referrer'] || ''),
      violatedDirective: sanitizeHtml(report['violated-directive'] || ''),
      effectiveDirective: sanitizeHtml(report['effective-directive'] || ''),
      originalPolicy: sanitizeHtml((report['original-policy'] || '').substring(0, 500)), // Limit policy length
      blockedUri: sanitizeHtml(report['blocked-uri'] || ''),
      lineNumber: Number.isInteger(report['line-number']) ? report['line-number'] : 0,
      columnNumber: Number.isInteger(report['column-number']) ? report['column-number'] : 0,
      sourceFile: sanitizeHtml(report['source-file'] || ''),
      statusCode: Number.isInteger(report['status-code']) ? report['status-code'] : 0,
      scriptSample: sanitizeHtml((report['script-sample'] || '').substring(0, 200)) // Limit script sample
    };

    // Analyze violation severity
    const analysis = analyzeCSPViolation(report);

    // Log violation with appropriate severity
    const logMessage = `CSP Violation: ${sanitizedReport.violatedDirective} blocked ${sanitizedReport.blockedUri}`;
    
    switch (analysis.severity) {
      case 'CRITICAL':
        SecureLogger.error(`CRITICAL CSP VIOLATION: ${logMessage} - Potential XSS attack detected`);
        break;
      case 'HIGH':
        SecureLogger.error(`HIGH CSP VIOLATION: ${logMessage}`);
        break;
      case 'MEDIUM':
        SecureLogger.warn(`MEDIUM CSP VIOLATION: ${logMessage}`);
        break;
      case 'LOW':
        SecureLogger.info(`LOW CSP VIOLATION: ${logMessage}`);
        break;
    }

    // Store violation data for security analysis
    const violationRecord = {
      timestamp: new Date().toISOString(),
      clientIp: clientIp.substring(0, 10) + '...', // Partial IP for privacy
      userAgent: sanitizeHtml((request.headers.get('user-agent') || '').substring(0, 200)),
      report: sanitizedReport,
      analysis: analysis
    };

    // In production, this would be stored in a security database
    // For now, we log it comprehensively
    SecureLogger.info(`CSP Violation Report: ${JSON.stringify(violationRecord)}`);

    // Trigger security alerts for critical violations
    if (analysis.actionRequired) {
      SecureLogger.error(`SECURITY ALERT: CSP violation requires immediate attention - ${analysis.threatType}`);
      
      // In production, this would:
      // - Send to security team
      // - Trigger incident response
      // - Block suspicious IPs
    }

    return NextResponse.json(
      { 
        status: 'received',
        id: `csp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date().toISOString()
      },
      { 
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache, no-store, must-revalidate'
        }
      }
    );

  } catch (error) {
    const secureError = processError(error, {
      endpoint: 'csp-report',
      clientIp: request.ip?.substring(0, 10) + '...'
    });

    SecureLogger.error('CSP report processing failed', error as Error);

    let status = 400;
    if (error instanceof SecurityError) {
      status = error.code === 'REPORT_TOO_LARGE' ? 413 : 400;
    }

    return NextResponse.json(
      { error: 'Failed to process CSP report' },
      { status }
    );
  }
}

// Block other HTTP methods
export async function GET() {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
}

export async function PUT() {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
}

export async function DELETE() {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
}