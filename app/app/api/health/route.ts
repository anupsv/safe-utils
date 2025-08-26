/**
 * Health check endpoint for container orchestration
 * Provides secure health status without exposing sensitive information
 */

import { NextResponse } from 'next/server';
import { cryptoIntegrity } from '@/lib/crypto-integrity';
import { getErrorStats } from '@/lib/secure-error-handler';

export async function GET(): Promise<NextResponse> {
  try {
    const startTime = Date.now();
    
    // Basic health checks
    const checks = {
      timestamp: new Date().toISOString(),
      status: 'healthy',
      uptime: process.uptime(),
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
      },
      nodejs: process.version,
      environment: process.env.NODE_ENV,
    };

    // Cryptographic integrity check
    const integrityStatus = cryptoIntegrity.getStatus();
    if (integrityStatus.status === 'COMPROMISED') {
      return NextResponse.json(
        {
          status: 'unhealthy',
          error: 'Cryptographic integrity compromised',
          timestamp: checks.timestamp,
        },
        { status: 503 }
      );
    }

    // Error rate check
    const errorStats = getErrorStats();
    const criticalErrors = errorStats.errorsBySeverity[4] || 0; // Critical errors
    if (criticalErrors > 10) {
      return NextResponse.json(
        {
          status: 'degraded',
          warning: 'High critical error rate detected',
          timestamp: checks.timestamp,
        },
        { status: 200 }
      );
    }

    const responseTime = Date.now() - startTime;
    
    return NextResponse.json(
      {
        ...checks,
        responseTime: `${responseTime}ms`,
        security: {
          integrityStatus: integrityStatus.status,
          totalErrors: errorStats.totalErrors,
        },
      },
      { 
        status: 200,
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Content-Type': 'application/json',
        },
      }
    );
  } catch (error) {
    return NextResponse.json(
      {
        status: 'unhealthy',
        error: 'Health check failed',
        timestamp: new Date().toISOString(),
      },
      { status: 503 }
    );
  }
}

// Only allow GET requests
export async function POST() {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
}

export async function PUT() {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
}

export async function DELETE() {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
}