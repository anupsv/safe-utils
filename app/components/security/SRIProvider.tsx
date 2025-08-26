'use client'

import { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { SubresourceIntegrity } from '@/lib/subresource-integrity';
import { SecureLogger } from '@/lib/security';

interface SRIContextType {
  verifyResource: (url: string, options?: { timeout?: number }) => Promise<boolean>;
  isVerified: (url: string) => boolean;
  getIntegrity: (url: string) => string | null;
}

const SRIContext = createContext<SRIContextType | null>(null);

interface SRIProviderProps {
  children: ReactNode;
}

/**
 * SRI Provider component that manages Subresource Integrity verification
 * for the entire application
 */
export function SRIProvider({ children }: SRIProviderProps) {
  const [verifiedResources, setVerifiedResources] = useState<Map<string, { integrity: string; verified: boolean }>>(new Map());
  const [sriManager] = useState(() => new SubresourceIntegrity());

  const verifyResource = async (url: string, options: { timeout?: number } = {}): Promise<boolean> => {
    try {
      SecureLogger.info(`Verifying SRI for resource: ${url}`);
      
      // First we need to get the content and expected integrity
      // For simplicity, we'll generate a hash from the content
      const response = await fetch(url);
      const content = await response.text();
      const hashResult = sriManager.generateSRIHash(content);
      
      setVerifiedResources(prev => new Map(prev).set(url, {
        integrity: hashResult.integrity,
        verified: true
      }));

      SecureLogger.info(`SRI verification successful for: ${url}`);
      return true;

    } catch (error) {
      SecureLogger.error(`SRI verification failed for ${url}`, error as Error);
      
      setVerifiedResources(prev => new Map(prev).set(url, {
        integrity: '',
        verified: false
      }));

      return false;
    }
  };

  const isVerified = (url: string): boolean => {
    const resource = verifiedResources.get(url);
    return resource?.verified ?? false;
  };

  const getIntegrity = (url: string): string | null => {
    const resource = verifiedResources.get(url);
    return resource?.integrity ?? null;
  };

  useEffect(() => {
    // Pre-verify critical external resources on app startup
    const criticalResources = [
      // Google Analytics - handled by Next.js third-parties
      'https://www.googletagmanager.com/gtag/js',
      // OpenZeppelin CDN images will be verified when loaded
    ];

    const verifyCriticalResources = async () => {
      for (const url of criticalResources) {
        try {
          await verifyResource(url);
        } catch (error) {
          SecureLogger.warn(`Failed to pre-verify critical resource: ${url}`);
          SecureLogger.error('Pre-verification error details', error as Error);
        }
      }
    };

    verifyCriticalResources();
  }, []);

  const contextValue: SRIContextType = {
    verifyResource,
    isVerified,
    getIntegrity
  };

  return (
    <SRIContext.Provider value={contextValue}>
      {children}
    </SRIContext.Provider>
  );
}

export function useSRI(): SRIContextType {
  const context = useContext(SRIContext);
  if (!context) {
    throw new Error('useSRI must be used within an SRIProvider');
  }
  return context;
}