/**
 * Security threat alerts API endpoint
 * Manages and reports active security threats
 */

import { NextRequest, NextResponse } from 'next/server';
import { SecureLogger, processError, SecurityError } from '@/lib/security';
import { sanitizeHtml } from '@/lib/secure-output';

interface ThreatAlert {
  id: string;
  timestamp: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  type: string;
  description: string;
  source?: string;
  resolved: boolean;
  resolvedAt?: string;
  resolvedBy?: string;
  metadata: Record<string, any>;
}

/**
 * Threat management system
 */
class ThreatManager {
  private static instance: ThreatManager;
  private threats: Map<string, ThreatAlert> = new Map();
  private maxThreats = 1000;

  public static getInstance(): ThreatManager {
    if (!ThreatManager.instance) {
      ThreatManager.instance = new ThreatManager();
    }
    return ThreatManager.instance;
  }

  public createThreat(
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
    type: string,
    description: string,
    source?: string,
    metadata: Record<string, any> = {}
  ): ThreatAlert {
    const threat: ThreatAlert = {
      id: `threat_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      severity,
      type: sanitizeHtml(type),
      description: sanitizeHtml(description),
      source: source ? sanitizeHtml(source) : undefined,
      resolved: false,
      metadata: this.sanitizeMetadata(metadata)
    };

    this.threats.set(threat.id, threat);

    // Cleanup old threats if we hit the limit
    if (this.threats.size > this.maxThreats) {
      const oldestKey = Array.from(this.threats.keys())[0];
      this.threats.delete(oldestKey);
    }

    SecureLogger.warn(`New ${severity} threat created: ${type} - ${description}`);
    return threat;
  }

  public resolveThreat(id: string, resolvedBy?: string): boolean {
    const threat = this.threats.get(id);
    if (!threat) {
      return false;
    }

    threat.resolved = true;
    threat.resolvedAt = new Date().toISOString();
    threat.resolvedBy = resolvedBy ? sanitizeHtml(resolvedBy) : 'system';

    this.threats.set(id, threat);
    SecureLogger.info(`Threat resolved: ${id} by ${threat.resolvedBy}`);
    return true;
  }

  public getThreats(options: {
    resolved?: boolean;
    severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    limit?: number;
    offset?: number;
  } = {}): ThreatAlert[] {
    let threats = Array.from(this.threats.values());

    // Filter by resolution status
    if (options.resolved !== undefined) {
      threats = threats.filter(t => t.resolved === options.resolved);
    }

    // Filter by severity
    if (options.severity) {
      threats = threats.filter(t => t.severity === options.severity);
    }

    // Sort by timestamp (newest first)
    threats.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    // Apply pagination
    const offset = options.offset || 0;
    const limit = Math.min(options.limit || 100, 1000);
    
    return threats.slice(offset, offset + limit);
  }

  public getThreatById(id: string): ThreatAlert | undefined {
    return this.threats.get(id);
  }

  public getStats(): {
    total: number;
    active: number;
    resolved: number;
    bySeverity: Record<string, number>;
  } {
    const threats = Array.from(this.threats.values());
    const stats = {
      total: threats.length,
      active: threats.filter(t => !t.resolved).length,
      resolved: threats.filter(t => t.resolved).length,
      bySeverity: {
        CRITICAL: threats.filter(t => t.severity === 'CRITICAL').length,
        HIGH: threats.filter(t => t.severity === 'HIGH').length,
        MEDIUM: threats.filter(t => t.severity === 'MEDIUM').length,
        LOW: threats.filter(t => t.severity === 'LOW').length
      }
    };

    return stats;
  }

  private sanitizeMetadata(metadata: Record<string, any>): Record<string, any> {
    const sanitized: Record<string, any> = {};
    
    for (const [key, value] of Object.entries(metadata)) {
      const sanitizedKey = sanitizeHtml(key.substring(0, 50));
      
      if (typeof value === 'string') {
        sanitized[sanitizedKey] = sanitizeHtml(value.substring(0, 500));
      } else if (typeof value === 'number' || typeof value === 'boolean') {
        sanitized[sanitizedKey] = value;
      } else if (Array.isArray(value)) {
        sanitized[sanitizedKey] = value.slice(0, 10).map(v => 
          typeof v === 'string' ? sanitizeHtml(v.substring(0, 100)) : v
        );
      }
    }

    return sanitized;
  }

  public clearResolvedThreats(): number {
    const resolved = Array.from(this.threats.values()).filter(t => t.resolved);
    resolved.forEach(threat => this.threats.delete(threat.id));
    
    SecureLogger.info(`Cleared ${resolved.length} resolved threats`);
    return resolved.length;
  }
}

const threatManager = ThreatManager.getInstance();

// Create some demo threats for testing
setTimeout(() => {
  threatManager.createThreat(
    'MEDIUM',
    'RATE_LIMIT_EXCEEDED',
    'Multiple rate limit violations detected from same IP range',
    'rate_limiter',
    { ipRange: '192.168.1.0/24', attempts: 150 }
  );

  threatManager.createThreat(
    'HIGH',
    'SUSPICIOUS_USER_AGENT',
    'Automated scanning tool detected',
    'user_agent_analyzer',
    { userAgent: 'Nmap Scripting Engine', requestCount: 25 }
  );
}, 5000);

export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    const { searchParams } = new URL(request.url);
    
    // Parse query parameters
    const resolved = searchParams.get('resolved');
    const severity = searchParams.get('severity') as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null;
    const limit = parseInt(searchParams.get('limit') || '50');
    const offset = parseInt(searchParams.get('offset') || '0');
    const statsOnly = searchParams.get('stats') === 'true';

    // Validate parameters
    if (severity && !['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(severity)) {
      throw new SecurityError('Invalid severity parameter', 'INVALID_SEVERITY');
    }

    if (limit > 1000 || limit < 1) {
      throw new SecurityError('Invalid limit parameter (1-1000)', 'INVALID_LIMIT');
    }

    if (offset < 0) {
      throw new SecurityError('Invalid offset parameter', 'INVALID_OFFSET');
    }

    // Get statistics if requested
    if (statsOnly) {
      const stats = threatManager.getStats();
      return NextResponse.json(
        { stats },
        {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache, no-store, must-revalidate'
          }
        }
      );
    }

    // Get threats with filters
    const options: any = { limit, offset };
    if (resolved !== null) {
      options.resolved = resolved === 'true';
    }
    if (severity) {
      options.severity = severity;
    }

    const threats = threatManager.getThreats(options);
    const stats = threatManager.getStats();

    const response = {
      threats,
      stats,
      pagination: {
        limit,
        offset,
        total: stats.total
      },
      timestamp: new Date().toISOString()
    };

    SecureLogger.info(`Threats API called: ${threats.length} threats returned`);

    return NextResponse.json(
      response,
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'X-Threat-Count': threats.length.toString(),
          'X-Active-Threats': stats.active.toString()
        }
      }
    );

  } catch (error) {
    const secureError = processError(error, {
      endpoint: 'threats',
      query: request.url
    });

    SecureLogger.error('Threats API failed', error as Error);

    return NextResponse.json(
      { 
        error: 'Failed to retrieve threat data',
        timestamp: new Date().toISOString()
      },
      { status: 400 }
    );
  }
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    // Validate content type
    const contentType = request.headers.get('content-type');
    if (!contentType?.includes('application/json')) {
      throw new SecurityError('Invalid content type', 'INVALID_CONTENT_TYPE');
    }

    const body = await request.json();

    // Validate required fields
    const { severity, type, description, source, metadata } = body;
    
    if (!severity || !type || !description) {
      throw new SecurityError('Missing required fields: severity, type, description', 'MISSING_FIELDS');
    }

    // Validate severity
    if (!['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(severity)) {
      throw new SecurityError('Invalid severity level', 'INVALID_SEVERITY');
    }

    // Create the threat
    const threat = threatManager.createThreat(
      severity,
      type,
      description,
      source,
      metadata || {}
    );

    return NextResponse.json(
      {
        threat,
        status: 'created',
        timestamp: new Date().toISOString()
      },
      { status: 201 }
    );

  } catch (error) {
    const secureError = processError(error, {
      endpoint: 'threats-create'
    });

    SecureLogger.error('Threat creation failed', error as Error);

    return NextResponse.json(
      { error: 'Failed to create threat alert' },
      { status: 400 }
    );
  }
}

export async function PATCH(request: NextRequest): Promise<NextResponse> {
  try {
    const { searchParams } = new URL(request.url);
    const threatId = searchParams.get('id');
    const action = searchParams.get('action');

    if (!threatId) {
      throw new SecurityError('Missing threat ID', 'MISSING_THREAT_ID');
    }

    if (action === 'resolve') {
      const body = await request.json().catch(() => ({}));
      const resolvedBy = body.resolvedBy || 'api_user';

      const success = threatManager.resolveThreat(threatId, resolvedBy);
      
      if (!success) {
        return NextResponse.json(
          { error: 'Threat not found' },
          { status: 404 }
        );
      }

      const updatedThreat = threatManager.getThreatById(threatId);
      
      return NextResponse.json(
        {
          threat: updatedThreat,
          status: 'resolved',
          timestamp: new Date().toISOString()
        },
        { status: 200 }
      );
    }

    throw new SecurityError('Invalid action', 'INVALID_ACTION');

  } catch (error) {
    const secureError = processError(error, {
      endpoint: 'threats-update'
    });

    SecureLogger.error('Threat update failed', error as Error);

    return NextResponse.json(
      { error: 'Failed to update threat' },
      { status: 400 }
    );
  }
}

// Export threat manager for use by other modules
export { threatManager as ThreatManager };