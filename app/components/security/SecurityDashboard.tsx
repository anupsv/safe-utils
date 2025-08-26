/**
 * Comprehensive security monitoring dashboard
 * Real-time security metrics and threat analysis
 */

'use client';

import React, { useState, useEffect } from 'react';
import { SecureLogger } from '@/lib/security';
import { SRIManager } from '@/lib/subresource-integrity';

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

interface ThreatAlert {
  id: string;
  timestamp: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  type: string;
  description: string;
  source?: string;
  resolved: boolean;
}

export default function SecurityDashboard(): JSX.Element {
  const [metrics, setMetrics] = useState<SecurityMetrics>({
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
  });

  const [threats, setThreats] = useState<ThreatAlert[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Fetch security metrics
  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        setIsLoading(true);
        
        // Get SRI statistics
        const sriStats = SRIManager.getVerificationStats();
        
        // Simulate fetching other security metrics
        // In production, this would call actual monitoring APIs
        const response = await fetch('/api/security/metrics', {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
            'Cache-Control': 'no-cache'
          }
        });

        if (response.ok) {
          const data = await response.json();
          setMetrics({
            ...data,
            sriVerifications: {
              successful: sriStats.verifiedCount,
              failed: sriStats.failedCount,
              total: sriStats.verifiedCount + sriStats.failedCount
            }
          });
        } else {
          // Fallback to demo data if API not available
          setMetrics(prev => ({
            ...prev,
            timestamp: new Date().toISOString(),
            sriVerifications: {
              successful: sriStats.verifiedCount,
              failed: sriStats.failedCount,
              total: sriStats.verifiedCount + sriStats.failedCount
            }
          }));
        }

        // Fetch threat alerts
        const threatResponse = await fetch('/api/security/threats', {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
            'Cache-Control': 'no-cache'
          }
        });

        if (threatResponse.ok) {
          const threatData = await threatResponse.json();
          setThreats(threatData.threats || []);
        }

      } catch (err) {
        setError('Failed to fetch security metrics');
        SecureLogger.error('Security dashboard fetch failed', err as Error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchMetrics();
    const interval = setInterval(fetchMetrics, 30000); // Update every 30 seconds

    return () => clearInterval(interval);
  }, []);

  const getStatusColor = (status: string): string => {
    switch (status) {
      case 'secure': return 'text-green-600 bg-green-100';
      case 'warning': return 'text-yellow-600 bg-yellow-100';
      case 'critical': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getSeverityColor = (severity: string): string => {
    switch (severity) {
      case 'CRITICAL': return 'text-red-700 bg-red-100 border-red-200';
      case 'HIGH': return 'text-orange-700 bg-orange-100 border-orange-200';
      case 'MEDIUM': return 'text-yellow-700 bg-yellow-100 border-yellow-200';
      case 'LOW': return 'text-blue-700 bg-blue-100 border-blue-200';
      default: return 'text-gray-700 bg-gray-100 border-gray-200';
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading security metrics...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="bg-red-100 border border-red-400 text-red-700 px-6 py-4 rounded-lg">
          <h3 className="font-bold">Error</h3>
          <p>{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Security Dashboard</h1>
          <p className="mt-2 text-gray-600">Real-time security monitoring and threat analysis</p>
          <p className="text-sm text-gray-500">Last updated: {new Date(metrics.timestamp).toLocaleString()}</p>
        </div>

        {/* System Status */}
        <div className="mb-6">
          <div className={`inline-flex items-center px-4 py-2 rounded-full text-sm font-medium ${getStatusColor(metrics.systemStatus)}`}>
            <div className="w-2 h-2 bg-current rounded-full mr-2"></div>
            System Status: {metrics.systemStatus.toUpperCase()}
          </div>
        </div>

        {/* Metrics Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {/* CSRF Protection */}
          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center">
                    <span className="text-white text-sm font-bold">🛡️</span>
                  </div>
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">CSRF Attacks Blocked</dt>
                    <dd className="text-lg font-medium text-gray-900">{metrics.csrfAttemptsBlocked}</dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>

          {/* Rate Limiting */}
          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className="w-8 h-8 bg-yellow-500 rounded-full flex items-center justify-center">
                    <span className="text-white text-sm font-bold">⚡</span>
                  </div>
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">Rate Limit Violations</dt>
                    <dd className="text-lg font-medium text-gray-900">{metrics.rateLimitViolations}</dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>

          {/* SRI Verifications */}
          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center">
                    <span className="text-white text-sm font-bold">✓</span>
                  </div>
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">SRI Verifications</dt>
                    <dd className="text-lg font-medium text-gray-900">
                      {metrics.sriVerifications.successful}/{metrics.sriVerifications.total}
                    </dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>

          {/* Input Validation */}
          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className="w-8 h-8 bg-red-500 rounded-full flex items-center justify-center">
                    <span className="text-white text-sm font-bold">🚫</span>
                  </div>
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-gray-500 truncate">Validation Failures</dt>
                    <dd className="text-lg font-medium text-gray-900">{metrics.inputValidationFailures}</dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* CSP Violations Chart */}
        <div className="bg-white shadow rounded-lg mb-8">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-medium text-gray-900">Content Security Policy Violations</h3>
          </div>
          <div className="p-6">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-red-600">{metrics.cspViolations.critical}</div>
                <div className="text-sm text-gray-500">Critical</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-orange-600">{metrics.cspViolations.high}</div>
                <div className="text-sm text-gray-500">High</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-yellow-600">{metrics.cspViolations.medium}</div>
                <div className="text-sm text-gray-500">Medium</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-600">{metrics.cspViolations.low}</div>
                <div className="text-sm text-gray-500">Low</div>
              </div>
            </div>
          </div>
        </div>

        {/* Threat Alerts */}
        <div className="bg-white shadow rounded-lg">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-medium text-gray-900">Recent Threat Alerts</h3>
          </div>
          <div className="divide-y divide-gray-200">
            {threats.length === 0 ? (
              <div className="px-6 py-8 text-center text-gray-500">
                <div className="text-4xl mb-2">🎉</div>
                <p>No active threats detected</p>
                <p className="text-sm">System is secure</p>
              </div>
            ) : (
              threats.slice(0, 10).map((threat) => (
                <div key={threat.id} className="px-6 py-4">
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center">
                        <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full border ${getSeverityColor(threat.severity)}`}>
                          {threat.severity}
                        </span>
                        <span className="ml-2 text-sm font-medium text-gray-900">{threat.type}</span>
                        {threat.resolved && (
                          <span className="ml-2 inline-flex px-2 py-1 text-xs font-medium text-green-700 bg-green-100 border border-green-200 rounded-full">
                            Resolved
                          </span>
                        )}
                      </div>
                      <p className="mt-1 text-sm text-gray-600">{threat.description}</p>
                      <p className="mt-1 text-xs text-gray-400">
                        {new Date(threat.timestamp).toLocaleString()}
                        {threat.source && ` • Source: ${threat.source}`}
                      </p>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Suspicious Activities */}
        {metrics.suspiciousActivities.length > 0 && (
          <div className="mt-8 bg-yellow-50 border border-yellow-200 rounded-lg">
            <div className="px-6 py-4 border-b border-yellow-200">
              <h3 className="text-lg font-medium text-yellow-800">Suspicious Activities</h3>
            </div>
            <div className="p-6">
              <ul className="space-y-2">
                {metrics.suspiciousActivities.map((activity, index) => (
                  <li key={index} className="text-sm text-yellow-700">
                    • {activity}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}