/**
 * Comprehensive audit trail system
 * Tracks all security-relevant operations and user actions
 */

import { SecureLogger, processError, SecurityError } from '@/lib/security';
import { sanitizeHtml } from '@/lib/secure-output';
import { createHash } from 'crypto';

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  userId?: string;
  sessionId?: string;
  ipAddress: string;
  userAgent: string;
  action: string;
  resource: string;
  outcome: 'SUCCESS' | 'FAILURE' | 'ERROR';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  details: Record<string, any>;
  metadata: {
    requestId?: string;
    apiVersion?: string;
    clientVersion?: string;
    executionTime?: number;
  };
  hash: string;
  previousHash?: string;
}

export interface AuditQuery {
  userId?: string;
  action?: string;
  resource?: string;
  outcome?: 'SUCCESS' | 'FAILURE' | 'ERROR';
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  startTime?: string;
  endTime?: string;
  ipAddress?: string;
  limit?: number;
  offset?: number;
}

/**
 * Secure audit trail manager with blockchain-like integrity verification
 */
export class AuditTrailManager {
  private static instance: AuditTrailManager;
  private auditLog: Map<string, AuditLogEntry> = new Map();
  private indexByUser: Map<string, Set<string>> = new Map();
  private indexByAction: Map<string, Set<string>> = new Map();
  private indexByResource: Map<string, Set<string>> = new Map();
  private lastHash: string = this.generateGenesisHash();
  private maxEntries = 10000;

  public static getInstance(): AuditTrailManager {
    if (!AuditTrailManager.instance) {
      AuditTrailManager.instance = new AuditTrailManager();
    }
    return AuditTrailManager.instance;
  }

  /**
   * Log an audit entry with cryptographic integrity
   */
  public logAction(
    action: string,
    resource: string,
    outcome: 'SUCCESS' | 'FAILURE' | 'ERROR',
    details: Record<string, any> = {},
    context: {
      userId?: string;
      sessionId?: string;
      ipAddress: string;
      userAgent: string;
      requestId?: string;
      executionTime?: number;
    }
  ): AuditLogEntry {
    try {
      const timestamp = new Date().toISOString();
      const id = `audit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

      // Determine severity based on outcome and action
      const severity = this.determineSeverity(action, outcome, details);

      // Sanitize all input data
      const sanitizedDetails = this.sanitizeDetails(details);
      const sanitizedContext = this.sanitizeContext(context);

      // Create audit entry
      const entry: AuditLogEntry = {
        id,
        timestamp,
        userId: sanitizedContext.userId,
        sessionId: sanitizedContext.sessionId,
        ipAddress: this.maskIP(sanitizedContext.ipAddress),
        userAgent: sanitizedContext.userAgent.substring(0, 200),
        action: sanitizeHtml(action),
        resource: sanitizeHtml(resource),
        outcome,
        severity,
        details: sanitizedDetails,
        metadata: {
          requestId: sanitizedContext.requestId,
          apiVersion: '2.0.0',
          clientVersion: 'safe-utils-1.0.0',
          executionTime: sanitizedContext.executionTime
        },
        hash: '',
        previousHash: this.lastHash
      };

      // Generate cryptographic hash for integrity
      entry.hash = this.generateEntryHash(entry);
      this.lastHash = entry.hash;

      // Store the entry
      this.auditLog.set(id, entry);

      // Update indexes for faster queries
      this.updateIndexes(entry);

      // Cleanup old entries if needed
      this.cleanupOldEntries();

      // Log to secure logger
      SecureLogger.info(`Audit: ${action} on ${resource} - ${outcome} (${severity})`);

      return entry;

    } catch (error) {
      const fallbackEntry = this.createFallbackEntry(action, resource, 'ERROR', error);
      SecureLogger.error('Audit logging failed', error as Error);
      return fallbackEntry;
    }
  }

  /**
   * Query audit logs with filtering and pagination
   */
  public queryLogs(query: AuditQuery = {}): {
    entries: AuditLogEntry[];
    total: number;
    hasMore: boolean;
  } {
    try {
      let entries = Array.from(this.auditLog.values());

      // Apply filters
      if (query.userId) {
        const userEntryIds = this.indexByUser.get(query.userId) || new Set();
        entries = entries.filter(e => userEntryIds.has(e.id));
      }

      if (query.action) {
        const actionEntryIds = this.indexByAction.get(query.action) || new Set();
        entries = entries.filter(e => actionEntryIds.has(e.id));
      }

      if (query.resource) {
        const resourceEntryIds = this.indexByResource.get(query.resource) || new Set();
        entries = entries.filter(e => resourceEntryIds.has(e.id));
      }

      if (query.outcome) {
        entries = entries.filter(e => e.outcome === query.outcome);
      }

      if (query.severity) {
        entries = entries.filter(e => e.severity === query.severity);
      }

      if (query.startTime) {
        const startTime = new Date(query.startTime).getTime();
        entries = entries.filter(e => new Date(e.timestamp).getTime() >= startTime);
      }

      if (query.endTime) {
        const endTime = new Date(query.endTime).getTime();
        entries = entries.filter(e => new Date(e.timestamp).getTime() <= endTime);
      }

      if (query.ipAddress) {
        const maskedQuery = this.maskIP(query.ipAddress);
        entries = entries.filter(e => e.ipAddress === maskedQuery);
      }

      // Sort by timestamp (newest first)
      entries.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

      const total = entries.length;
      const limit = Math.min(query.limit || 100, 1000);
      const offset = query.offset || 0;

      const paginatedEntries = entries.slice(offset, offset + limit);
      const hasMore = offset + limit < total;

      SecureLogger.info(`Audit query executed: ${paginatedEntries.length}/${total} entries returned`);

      return {
        entries: paginatedEntries,
        total,
        hasMore
      };

    } catch (error) {
      SecureLogger.error('Audit query failed', error as Error);
      return {
        entries: [],
        total: 0,
        hasMore: false
      };
    }
  }

  /**
   * Verify audit trail integrity
   */
  public verifyIntegrity(): {
    isValid: boolean;
    corruptedEntries: string[];
    totalVerified: number;
  } {
    try {
      const entries = Array.from(this.auditLog.values())
        .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

      const corruptedEntries: string[] = [];
      let previousHash = this.generateGenesisHash();

      for (const entry of entries) {
        // Verify hash integrity
        const expectedHash = this.generateEntryHash({
          ...entry,
          hash: '',
          previousHash
        });

        if (entry.hash !== expectedHash) {
          corruptedEntries.push(entry.id);
          SecureLogger.error(`Audit integrity violation detected in entry: ${entry.id}`);
        }

        // Verify chain integrity
        if (entry.previousHash !== previousHash) {
          corruptedEntries.push(entry.id);
          SecureLogger.error(`Audit chain integrity violation detected in entry: ${entry.id}`);
        }

        previousHash = entry.hash;
      }

      const isValid = corruptedEntries.length === 0;
      
      if (isValid) {
        SecureLogger.info(`Audit integrity verification passed: ${entries.length} entries verified`);
      } else {
        SecureLogger.error(`Audit integrity verification failed: ${corruptedEntries.length} corrupted entries`);
      }

      return {
        isValid,
        corruptedEntries,
        totalVerified: entries.length
      };

    } catch (error) {
      SecureLogger.error('Audit integrity verification failed', error as Error);
      return {
        isValid: false,
        corruptedEntries: [],
        totalVerified: 0
      };
    }
  }

  /**
   * Get audit statistics
   */
  public getStatistics(): {
    totalEntries: number;
    entriesByOutcome: Record<string, number>;
    entriesBySeverity: Record<string, number>;
    entriesLast24h: number;
    mostCommonActions: Array<{ action: string; count: number }>;
    integrityStatus: 'VERIFIED' | 'CORRUPTED' | 'UNKNOWN';
  } {
    try {
      const entries = Array.from(this.auditLog.values());
      const last24h = Date.now() - 24 * 60 * 60 * 1000;

      const stats = {
        totalEntries: entries.length,
        entriesByOutcome: {
          SUCCESS: entries.filter(e => e.outcome === 'SUCCESS').length,
          FAILURE: entries.filter(e => e.outcome === 'FAILURE').length,
          ERROR: entries.filter(e => e.outcome === 'ERROR').length
        },
        entriesBySeverity: {
          LOW: entries.filter(e => e.severity === 'LOW').length,
          MEDIUM: entries.filter(e => e.severity === 'MEDIUM').length,
          HIGH: entries.filter(e => e.severity === 'HIGH').length,
          CRITICAL: entries.filter(e => e.severity === 'CRITICAL').length
        },
        entriesLast24h: entries.filter(e => new Date(e.timestamp).getTime() > last24h).length,
        mostCommonActions: this.getMostCommonActions(entries, 10),
        integrityStatus: 'UNKNOWN' as const
      };

      // Quick integrity check
      const integrity = this.verifyIntegrity();
      stats.integrityStatus = integrity.isValid ? 'VERIFIED' : 'CORRUPTED';

      return stats;

    } catch (error) {
      SecureLogger.error('Audit statistics generation failed', error as Error);
      return {
        totalEntries: 0,
        entriesByOutcome: { SUCCESS: 0, FAILURE: 0, ERROR: 0 },
        entriesBySeverity: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
        entriesLast24h: 0,
        mostCommonActions: [],
        integrityStatus: 'UNKNOWN'
      };
    }
  }

  private generateGenesisHash(): string {
    return createHash('sha256')
      .update('SafeUtils-AuditTrail-Genesis-2024')
      .digest('hex');
  }

  private generateEntryHash(entry: Omit<AuditLogEntry, 'hash'>): string {
    const hashData = {
      id: entry.id,
      timestamp: entry.timestamp,
      userId: entry.userId || '',
      action: entry.action,
      resource: entry.resource,
      outcome: entry.outcome,
      previousHash: entry.previousHash || ''
    };

    return createHash('sha256')
      .update(JSON.stringify(hashData))
      .digest('hex');
  }

  private determineSeverity(
    action: string,
    outcome: 'SUCCESS' | 'FAILURE' | 'ERROR',
    details: Record<string, any>
  ): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    // Critical actions
    if (outcome === 'ERROR' || outcome === 'FAILURE') {
      if (action.includes('auth') || action.includes('security') || action.includes('admin')) {
        return 'CRITICAL';
      }
      if (action.includes('transaction') || action.includes('hash') || action.includes('signature')) {
        return 'HIGH';
      }
      return 'MEDIUM';
    }

    // Successful actions
    if (action.includes('admin') || action.includes('security')) {
      return 'MEDIUM';
    }

    return 'LOW';
  }

  private sanitizeDetails(details: Record<string, any>): Record<string, any> {
    const sanitized: Record<string, any> = {};
    
    for (const [key, value] of Object.entries(details)) {
      const sanitizedKey = sanitizeHtml(key.substring(0, 100));
      
      if (typeof value === 'string') {
        sanitized[sanitizedKey] = sanitizeHtml(value.substring(0, 1000));
      } else if (typeof value === 'number' || typeof value === 'boolean') {
        sanitized[sanitizedKey] = value;
      } else if (Array.isArray(value)) {
        sanitized[sanitizedKey] = value.slice(0, 10).map(v => 
          typeof v === 'string' ? sanitizeHtml(v.substring(0, 200)) : v
        );
      } else if (typeof value === 'object' && value !== null) {
        // Recursively sanitize nested objects (limited depth)
        sanitized[sanitizedKey] = this.sanitizeDetails(value);
      }
    }

    return sanitized;
  }

  private sanitizeContext(context: any): any {
    return {
      userId: context.userId ? sanitizeHtml(context.userId.substring(0, 50)) : undefined,
      sessionId: context.sessionId ? sanitizeHtml(context.sessionId.substring(0, 100)) : undefined,
      ipAddress: context.ipAddress || 'unknown',
      userAgent: sanitizeHtml((context.userAgent || 'unknown').substring(0, 500)),
      requestId: context.requestId ? sanitizeHtml(context.requestId.substring(0, 100)) : undefined,
      executionTime: typeof context.executionTime === 'number' ? context.executionTime : undefined
    };
  }

  private maskIP(ip: string): string {
    if (!ip || ip === 'unknown') return 'unknown';
    
    // Mask last octet of IPv4 or last groups of IPv6 for privacy
    if (ip.includes('.')) {
      const parts = ip.split('.');
      if (parts.length === 4) {
        return `${parts[0]}.${parts[1]}.${parts[2]}.xxx`;
      }
    } else if (ip.includes(':')) {
      const parts = ip.split(':');
      if (parts.length >= 4) {
        return parts.slice(0, 4).join(':') + ':xxxx:xxxx:xxxx:xxxx';
      }
    }
    
    return ip.substring(0, 10) + 'xxx';
  }

  private updateIndexes(entry: AuditLogEntry): void {
    if (entry.userId) {
      if (!this.indexByUser.has(entry.userId)) {
        this.indexByUser.set(entry.userId, new Set());
      }
      this.indexByUser.get(entry.userId)!.add(entry.id);
    }

    if (!this.indexByAction.has(entry.action)) {
      this.indexByAction.set(entry.action, new Set());
    }
    this.indexByAction.get(entry.action)!.add(entry.id);

    if (!this.indexByResource.has(entry.resource)) {
      this.indexByResource.set(entry.resource, new Set());
    }
    this.indexByResource.get(entry.resource)!.add(entry.id);
  }

  private cleanupOldEntries(): void {
    if (this.auditLog.size <= this.maxEntries) return;

    const entries = Array.from(this.auditLog.values())
      .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

    const toDelete = entries.slice(0, this.auditLog.size - this.maxEntries);
    
    for (const entry of toDelete) {
      this.auditLog.delete(entry.id);
      
      // Clean up indexes
      if (entry.userId) {
        this.indexByUser.get(entry.userId)?.delete(entry.id);
      }
      this.indexByAction.get(entry.action)?.delete(entry.id);
      this.indexByResource.get(entry.resource)?.delete(entry.id);
    }

    SecureLogger.info(`Audit trail cleanup: removed ${toDelete.length} old entries`);
  }

  private getMostCommonActions(entries: AuditLogEntry[], limit: number): Array<{ action: string; count: number }> {
    const actionCounts = new Map<string, number>();
    
    for (const entry of entries) {
      actionCounts.set(entry.action, (actionCounts.get(entry.action) || 0) + 1);
    }

    return Array.from(actionCounts.entries())
      .map(([action, count]) => ({ action, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, limit);
  }

  private createFallbackEntry(action: string, resource: string, outcome: 'ERROR', error: any): AuditLogEntry {
    const timestamp = new Date().toISOString();
    const id = `audit_fallback_${Date.now()}`;

    return {
      id,
      timestamp,
      ipAddress: 'system',
      userAgent: 'internal',
      action: sanitizeHtml(action),
      resource: sanitizeHtml(resource),
      outcome,
      severity: 'CRITICAL',
      details: {
        error: 'Audit logging system failure',
        originalError: error?.message ? sanitizeHtml(error.message.substring(0, 200)) : 'Unknown error'
      },
      metadata: {
        apiVersion: '2.0.0',
        clientVersion: 'safe-utils-1.0.0'
      },
      hash: 'fallback_hash',
      previousHash: this.lastHash
    };
  }
}

// Export singleton instance
export const AuditTrail = AuditTrailManager.getInstance();