# Secure multi-stage Docker build for Safe Utils
# Addresses security vulnerabilities and follows best practices

# Build stage - use specific version and distroless approach
FROM node:20.11.1-alpine@sha256:c0a3badbd8a0a760de903e00cedbca94588e609299820557e72cba2a53dbaa2c AS builder

# Set build arguments for security
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

# Add metadata labels
LABEL maintainer="OpenZeppelin <security@openzeppelin.com>" \
      org.opencontainers.image.title="Safe Utils" \
      org.opencontainers.image.description="Secure Safe transaction hash calculator" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.created=$BUILD_DATE \
      org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.vendor="OpenZeppelin" \
      org.opencontainers.image.licenses="MIT"

# Create non-root user early for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001 -G nodejs

# Set secure working directory
WORKDIR /app

# Install security updates and minimal dependencies
RUN apk update && \
    apk upgrade && \
    apk add --no-cache \
        dumb-init=1.2.5-r2 \
        tini=0.19.0-r1 && \
    rm -rf /var/cache/apk/* /tmp/* /var/tmp/*

# Copy package files with proper ownership
COPY --chown=nextjs:nodejs app/package*.json ./

# Verify package integrity and install dependencies with security flags
RUN npm ci --only=production --no-audit --no-fund --ignore-scripts && \
    npm cache clean --force

# Copy source code with proper ownership
COPY --chown=nextjs:nodejs app/ ./

# Remove shell script dependency (security improvement)
# The secure API endpoint now handles hash calculations natively

# Build the application
RUN npm run build && \
    npm prune --production

# Remove development dependencies and clean up
RUN rm -rf .next/cache/webpack* && \
    rm -rf node_modules/.cache && \
    find . -name "*.md" -type f -delete && \
    find . -name "*.map" -type f -delete

# Production stage - use distroless for minimal attack surface
FROM gcr.io/distroless/nodejs20-debian12@sha256:a7218b8af5a4c1b9c41e4830e64e5afd77d4a2f96b2e6de2b8c4b8e6d4ed3b7e AS runner

# Add metadata labels
LABEL maintainer="OpenZeppelin <security@openzeppelin.com>" \
      org.opencontainers.image.title="Safe Utils Runtime" \
      org.opencontainers.image.description="Secure runtime for Safe Utils" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.created=$BUILD_DATE \
      org.opencontainers.image.revision=$VCS_REF

# Set environment variables for security and performance
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME="0.0.0.0" \
    NODE_OPTIONS="--max-old-space-size=2048 --max-http-header-size=8192" \
    TZ=UTC

# Create application directory
WORKDIR /app

# Copy application from builder with minimal files
COPY --from=builder --chown=nonroot:nonroot /app/next.config.js ./
COPY --from=builder --chown=nonroot:nonroot /app/package.json ./
COPY --from=builder --chown=nonroot:nonroot /app/.next/standalone ./
COPY --from=builder --chown=nonroot:nonroot /app/.next/static ./.next/static
COPY --from=builder --chown=nonroot:nonroot /app/public ./public

# Set file permissions for security
USER nonroot:nonroot

# Configure security settings
RUN ["chmod", "-R", "755", "/app"]

# Expose port with security context
EXPOSE 3000

# Health check for container orchestration
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD ["node", "-e", "require('http').get('http://localhost:3000/api/health', (res) => process.exit(res.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"]

# Use distroless entrypoint for security
ENTRYPOINT ["./server.js"]

# Development stage for local development (optional)
FROM node:20.11.1-alpine@sha256:c0a3badbd8a0a760de903e00cedbca94588e609299820557e72cba2a53dbaa2c AS development

WORKDIR /app

# Install development dependencies
RUN apk add --no-cache git && \
    addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001 -G nodejs

COPY --chown=nextjs:nodejs app/package*.json ./
RUN npm ci

COPY --chown=nextjs:nodejs app/ ./

USER nextjs

EXPOSE 3000

CMD ["npm", "run", "dev"]