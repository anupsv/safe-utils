/** @type {import('next').NextConfig} */
const nextConfig = {
  basePath: process.env.NEXT_PUBLIC_BASE_PATH || '', // will be either '/safe' or ''
  
  // Security headers
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'X-XSS-Protection',
            value: '1; mode=block',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
          {
            key: 'Permissions-Policy',
            value: 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), bluetooth=()',
          },
        ],
      },
    ];
  },

  // Security and performance optimizations
  poweredByHeader: false,
  compress: true,
  
  // Enable standalone output for Docker
  output: 'standalone',
  
  // Disable telemetry for privacy (Note: telemetry is not in experimental in newer Next.js versions)
  experimental: {
    // telemetry: false, // Removed as it's not a valid experimental option
  },

  // Webpack configuration for security
  webpack: (config, { dev, isServer }) => {
    // Security optimizations
    if (!dev) {
      config.optimization.minimize = true;
      
      // Remove source maps in production for security
      config.devtool = false;
    }

    return config;
  },

  // Image optimization security
  images: {
    domains: [],
    unoptimized: false,
    dangerouslyAllowSVG: false,
    contentSecurityPolicy: "default-src 'self'; script-src 'none'; sandbox;",
  },

  // Disable X-Powered-By header
  generateEtags: false,

  // Strict mode for better error catching
  reactStrictMode: true,

  // ESLint configuration
  eslint: {
    dirs: ['app', 'lib', 'components', 'utils', 'hooks'],
    ignoreDuringBuilds: false,
  },

  // TypeScript configuration
  typescript: {
    ignoreBuildErrors: false,
  },
}

module.exports = nextConfig