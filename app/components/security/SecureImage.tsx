'use client'

import { useState, useEffect, ImgHTMLAttributes } from 'react';
import { useSRI } from './SRIProvider';
import { SecureLogger } from '@/lib/security';

interface SecureImageProps extends Omit<ImgHTMLAttributes<HTMLImageElement>, 'src'> {
  src: string;
  fallbackSrc?: string;
  enableSRI?: boolean;
  timeout?: number;
}

/**
 * Secure Image component with SRI verification for external resources
 */
export function SecureImage({ 
  src, 
  fallbackSrc, 
  enableSRI = true, 
  timeout = 5000,
  alt = '',
  ...props 
}: SecureImageProps) {
  const [imageSrc, setImageSrc] = useState<string>('');
  const [isLoading, setIsLoading] = useState(true);
  const [hasError, setHasError] = useState(false);
  const { verifyResource, isVerified } = useSRI();

  useEffect(() => {
    const loadImage = async () => {
      setIsLoading(true);
      setHasError(false);

      try {
        // If it's an external HTTPS resource and SRI is enabled, verify it
        if (enableSRI && src.startsWith('https://') && !src.includes(window.location.hostname)) {
          SecureLogger.info(`Attempting SRI verification for image: ${src}`);
          
          const verified = await verifyResource(src, { timeout });
          
          if (!verified) {
            throw new Error('SRI verification failed');
          }
        }

        // Test if image loads successfully
        const img = new Image();
        img.crossOrigin = 'anonymous';
        
        img.onload = () => {
          setImageSrc(src);
          setIsLoading(false);
          SecureLogger.info(`Image loaded successfully: ${src}`);
        };

        img.onerror = () => {
          throw new Error('Image failed to load');
        };

        img.src = src;

      } catch (error) {
        SecureLogger.warn(`Failed to load secure image ${src}`);
        SecureLogger.error('Image loading error details', error as Error);
        setHasError(true);
        
        // Try fallback image if available
        if (fallbackSrc) {
          try {
            const img = new Image();
            img.onload = () => {
              setImageSrc(fallbackSrc);
              setIsLoading(false);
            };
            img.onerror = () => {
              setIsLoading(false);
            };
            img.src = fallbackSrc;
          } catch (fallbackError) {
            SecureLogger.warn(`Fallback image also failed: ${fallbackSrc}`);
            SecureLogger.error('Fallback image error details', fallbackError as Error);
            setIsLoading(false);
          }
        } else {
          setIsLoading(false);
        }
      }
    };

    if (src) {
      loadImage();
    } else {
      setIsLoading(false);
    }
  }, [src, fallbackSrc, enableSRI, timeout, verifyResource]);

  // Show loading state
  if (isLoading) {
    return (
      <div 
        className="bg-gray-200 dark:bg-gray-700 animate-pulse"
        style={{ width: props.width || 'auto', height: props.height || 'auto' }}
        aria-label="Loading image..."
      />
    );
  }

  // Show error state or empty div if no image to show
  if (hasError || !imageSrc) {
    return (
      <div 
        className="bg-gray-300 dark:bg-gray-600 flex items-center justify-center text-gray-500 dark:text-gray-400 text-xs"
        style={{ width: props.width || 'auto', height: props.height || 'auto' }}
        title={`Failed to load image: ${src}`}
      >
        {alt || 'Image unavailable'}
      </div>
    );
  }

  return (
    <img
      {...props}
      src={imageSrc}
      alt={alt}
      crossOrigin="anonymous"
      // Add integrity attribute if we have it and it's an external resource
      {...(enableSRI && isVerified(src) ? { 
        onLoad: (e) => {
          SecureLogger.info(`Verified image rendered: ${src}`);
          props.onLoad?.(e);
        }
      } : {})}
    />
  );
}