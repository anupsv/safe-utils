'use client'

import { useEffect, useState } from 'react';
import Script from 'next/script';
import { useSRI } from './SRIProvider';
import { SecureLogger } from '@/lib/security';

interface SecureGoogleAnalyticsProps {
  gaId: string;
  enableSRI?: boolean;
}

/**
 * Secure Google Analytics component with SRI verification
 * Falls back to standard Google Analytics if SRI verification fails
 */
export function SecureGoogleAnalytics({ 
  gaId, 
  enableSRI = true 
}: SecureGoogleAnalyticsProps) {
  const [isVerified, setIsVerified] = useState(!enableSRI);
  const [useStandardGA, setUseStandardGA] = useState(!enableSRI);
  const { verifyResource } = useSRI();

  useEffect(() => {
    const verifyGoogleAnalytics = async () => {
      if (!enableSRI) {
        setIsVerified(true);
        setUseStandardGA(true);
        return;
      }

      try {
        SecureLogger.info('Attempting SRI verification for Google Analytics');
        
        // Verify the main Google Analytics script
        const gtmUrl = `https://www.googletagmanager.com/gtag/js?id=${gaId}`;
        const verified = await verifyResource(gtmUrl, { timeout: 5000 });

        if (verified) {
          SecureLogger.info('Google Analytics SRI verification successful');
          setIsVerified(true);
          setUseStandardGA(true);
        } else {
          throw new Error('SRI verification failed');
        }

      } catch (error) {
        SecureLogger.warn('Google Analytics SRI verification failed, using standard implementation');
        SecureLogger.error('SRI verification error details', error as Error);
        // Fall back to standard Google Analytics without custom SRI
        setIsVerified(false);
        setUseStandardGA(true);
      }
    };

    verifyGoogleAnalytics();
  }, [gaId, enableSRI, verifyResource]);

  // Don't render anything until verification is complete
  if (!useStandardGA) {
    return null;
  }

  return (
    <>
      {/* Google Analytics gtag.js */}
      <Script
        src={`https://www.googletagmanager.com/gtag/js?id=${gaId}`}
        strategy="afterInteractive"
        onLoad={() => {
          SecureLogger.info(`Google Analytics loaded successfully ${isVerified ? 'with SRI verification' : 'without SRI verification'}`);
        }}
        onError={() => {
          SecureLogger.error('Google Analytics script failed to load');
        }}
      />
      
      {/* Google Analytics configuration */}
      <Script id="google-analytics" strategy="afterInteractive">
        {`
          window.dataLayer = window.dataLayer || [];
          function gtag(){dataLayer.push(arguments);}
          gtag('js', new Date());
          gtag('config', '${gaId}', {
            page_title: document.title,
            page_location: window.location.href,
            // Enhanced security and privacy settings
            anonymize_ip: true,
            allow_google_signals: false,
            allow_ad_personalization_signals: false,
            restricted_data_processing: true,
            // Custom dimensions for security monitoring
            custom_map: {
              'custom_dimension_1': 'sri_status'
            }
          });
          
          // Track SRI verification status
          gtag('event', 'sri_verification', {
            event_category: 'Security',
            event_label: '${isVerified ? 'verified' : 'unverified'}',
            value: ${isVerified ? 1 : 0}
          });

          // Enhanced security logging for analytics
          gtag('event', 'security_analytics_loaded', {
            event_category: 'Security',
            event_label: 'google_analytics',
            sri_verified: ${isVerified}
          });
        `}
      </Script>
    </>
  );
}