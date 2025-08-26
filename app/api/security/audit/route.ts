/**
 * Audit trail API endpoint
 * Provides access to security audit logs and integrity verification
 */

import { NextRequest, NextResponse } from 'next/server';
import { SecureLogger, processError, SecurityError } from '@/lib/security';
import { AuditTrail, AuditQuery } from '@/lib/audit-trail';

// Rate limiting for audit API
const auditRateLimiter = new Map<string, { count: number; resetTime: number }>();
const MAX_AUDIT_REQUESTS = 50; // per minute
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute

function checkAuditRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = auditRateLimiter.get(ip);

  if (!entry || now >= entry.resetTime) {
    auditRateLimiter.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return true;
  }

  if (entry.count >= MAX_AUDIT_REQUESTS) {
    return false;
  }

  entry.count++;
  return true;
}

export async function GET(request: NextRequest): Promise<NextResponse> {
  const startTime = Date.now();

  try {
    // Rate limiting
    const clientIp = request.ip || 
      request.headers.get('x-forwarded-for')?.split(',')[0] ||
      request.headers.get('x-real-ip') ||
      'unknown';

    if (!checkAuditRateLimit(clientIp)) {
      AuditTrail.logAction(
        'audit_api_rate_limit_exceeded',
        'audit_api',
        'FAILURE',
        { reason: 'Rate limit exceeded' },
        {
          ipAddress: clientIp,
          userAgent: request.headers.get('user-agent') || 'unknown'
        }
      );

      return NextResponse.json(
        { error: 'Rate limit exceeded' },
        { status: 429 }
      );
    }

    const { searchParams } = new URL(request.url);
    const action = searchParams.get('action');

    // Handle special actions
    if (action === 'verify') {
      return await handleIntegrityVerification(request, clientIp);
    }

    if (action === 'stats') {
      return await handleStatistics(request, clientIp);
    }

    // Build query from search parameters
    const query: AuditQuery = {};

    if (searchParams.get('userId')) {
      query.userId = searchParams.get('userId')!;
    }

    if (searchParams.get('action')) {
      query.action = searchParams.get('action')!;
    }

    if (searchParams.get('resource')) {
      query.resource = searchParams.get('resource')!;
    }

    if (searchParams.get('outcome')) {
      const outcome = searchParams.get('outcome')!;
      if (['SUCCESS', 'FAILURE', 'ERROR'].includes(outcome)) {
        query.outcome = outcome as 'SUCCESS' | 'FAILURE' | 'ERROR';
      }
    }

    if (searchParams.get('severity')) {
      const severity = searchParams.get('severity')!;
      if (['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(severity)) {
        query.severity = severity as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
      }
    }

    if (searchParams.get('startTime')) {
      query.startTime = searchParams.get('startTime')!;
    }

    if (searchParams.get('endTime')) {
      query.endTime = searchParams.get('endTime')!;
    }

    if (searchParams.get('limit')) {
      const limit = parseInt(searchParams.get('limit')!);
      if (!isNaN(limit) && limit > 0 && limit <= 1000) {
        query.limit = limit;
      }
    }

    if (searchParams.get('offset')) {
      const offset = parseInt(searchParams.get('offset')!);
      if (!isNaN(offset) && offset >= 0) {
        query.offset = offset;
      }
    }

    // Execute query
    const result = AuditTrail.queryLogs(query);
    const executionTime = Date.now() - startTime;

    // Log audit access
    AuditTrail.logAction(
      'audit_logs_accessed',
      'audit_api',
      'SUCCESS',
      {
        query,
        resultsCount: result.entries.length,
        totalResults: result.total
      },
      {
        ipAddress: clientIp,
        userAgent: request.headers.get('user-agent') || 'unknown',
        executionTime
      }
    );

    return NextResponse.json(
      {
        audit: result,
        metadata: {
          query,
          executionTime,
          timestamp: new Date().toISOString()
        }
      },
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'X-Audit-Results': result.entries.length.toString(),
          'X-Audit-Total': result.total.toString(),
          'X-Execution-Time': executionTime.toString()
        }
      }
    );

  } catch (error) {
    const executionTime = Date.now() - startTime;
    const secureError = processError(error, {
      endpoint: 'audit_logs',
      executionTime
    });

    AuditTrail.logAction(
      'audit_api_error',
      'audit_api',
      'ERROR',
      {
        error: secureError.userMessage,
        executionTime
      },
      {
        ipAddress: request.ip || 'unknown',
        userAgent: request.headers.get('user-agent') || 'unknown',
        executionTime
      }
    );

    SecureLogger.error('Audit API failed', error as Error);

    return NextResponse.json(
      {
        error: 'Failed to retrieve audit logs',
        timestamp: new Date().toISOString()
      },
      { status: 500 }
    );
  }
}

async function handleIntegrityVerification(request: NextRequest, clientIp: string): Promise<NextResponse> {
  const startTime = Date.now();

  try {
    const verification = AuditTrail.verifyIntegrity();
    const executionTime = Date.now() - startTime;

    AuditTrail.logAction(
      'audit_integrity_verification',
      'audit_system',
      verification.isValid ? 'SUCCESS' : 'FAILURE',
      {
        isValid: verification.isValid,
        totalVerified: verification.totalVerified,
        corruptedEntries: verification.corruptedEntries.length,
        executionTime
      },
      {
        ipAddress: clientIp,
        userAgent: request.headers.get('user-agent') || 'unknown',
        executionTime
      }
    );

    return NextResponse.json(
      {
        integrity: verification,
        metadata: {
          executionTime,
          timestamp: new Date().toISOString()
        }
      },
      {
        status: verification.isValid ? 200 : 500,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'X-Integrity-Status': verification.isValid ? 'VERIFIED' : 'CORRUPTED'
        }
      }
    );

  } catch (error) {
    const executionTime = Date.now() - startTime;
    SecureLogger.error('Audit integrity verification failed', error as Error);

    return NextResponse.json(
      {
        error: 'Failed to verify audit integrity',
        timestamp: new Date().toISOString()
      },
      { status: 500 }
    );
  }
}

async function handleStatistics(request: NextRequest, clientIp: string): Promise<NextResponse> {
  const startTime = Date.now();

  try {
    const statistics = AuditTrail.getStatistics();
    const executionTime = Date.now() - startTime;

    AuditTrail.logAction(
      'audit_statistics_accessed',
      'audit_api',
      'SUCCESS',
      {
        totalEntries: statistics.totalEntries,
        integrityStatus: statistics.integrityStatus,
        executionTime
      },
      {
        ipAddress: clientIp,
        userAgent: request.headers.get('user-agent') || 'unknown',
        executionTime
      }
    );

    return NextResponse.json(
      {
        statistics,
        metadata: {
          executionTime,
          timestamp: new Date().toISOString()
        }
      },
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'X-Total-Entries': statistics.totalEntries.toString(),
          'X-Integrity-Status': statistics.integrityStatus
        }
      }
    );

  } catch (error) {
    const executionTime = Date.now() - startTime;
    SecureLogger.error('Audit statistics failed', error as Error);

    return NextResponse.json(
      {
        error: 'Failed to retrieve audit statistics',
        timestamp: new Date().toISOString()
      },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  const startTime = Date.now();

  try {
    // Validate content type
    const contentType = request.headers.get('content-type');
    if (!contentType?.includes('application/json')) {
      throw new SecurityError('Invalid content type', 'INVALID_CONTENT_TYPE');
    }

    const clientIp = request.ip || 
      request.headers.get('x-forwarded-for')?.split(',')[0] ||
      request.headers.get('x-real-ip') ||
      'unknown';

    // Rate limiting
    if (!checkAuditRateLimit(clientIp)) {
      return NextResponse.json(
        { error: 'Rate limit exceeded' },
        { status: 429 }
      );
    }

    const body = await request.json();

    // Validate required fields
    const { action, resource, outcome, details, context } = body;

    if (!action || !resource || !outcome) {
      throw new SecurityError('Missing required fields: action, resource, outcome', 'MISSING_FIELDS');
    }

    if (!['SUCCESS', 'FAILURE', 'ERROR'].includes(outcome)) {
      throw new SecurityError('Invalid outcome value', 'INVALID_OUTCOME');
    }

    // Create audit entry
    const auditContext = {
      userId: context?.userId,
      sessionId: context?.sessionId,
      ipAddress: clientIp,
      userAgent: request.headers.get('user-agent') || 'unknown',
      requestId: context?.requestId,
      executionTime: context?.executionTime
    };

    const entry = AuditTrail.logAction(
      action,
      resource,
      outcome,
      details || {},
      auditContext
    );

    const executionTime = Date.now() - startTime;

    return NextResponse.json(
      {
        entry: {
          id: entry.id,
          timestamp: entry.timestamp,
          action: entry.action,
          resource: entry.resource,
          outcome: entry.outcome,
          severity: entry.severity
        },
        metadata: {
          executionTime,
          timestamp: new Date().toISOString()
        }
      },
      {
        status: 201,
        headers: {
          'Content-Type': 'application/json',
          'X-Audit-Entry-Id': entry.id
        }
      }
    );

  } catch (error) {
    const executionTime = Date.now() - startTime;
    const secureError = processError(error, {
      endpoint: 'audit_create',
      executionTime
    });

    SecureLogger.error('Audit creation failed', error as Error);

    return NextResponse.json(
      {
        error: 'Failed to create audit entry',
        timestamp: new Date().toISOString()
      },
      { status: 400 }
    );
  }
}

// Block other HTTP methods
export async function PUT(): Promise<NextResponse> {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
}

export async function DELETE(): Promise<NextResponse> {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
}

export async function PATCH(): Promise<NextResponse> {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
}