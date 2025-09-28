# Build stage
FROM node:20-slim AS builder

# Security: Use non-root user during build
RUN groupadd --system --gid 1001 nodejs && \
    useradd --system --uid 1001 --gid nodejs nodejs

WORKDIR /app

# Copy package files first (for better caching)
COPY app/package*.json ./

# Install dependencies (excluding the problematic preinstall-always-fail)
RUN npm ci --ignore-scripts && \
    npm cache clean --force

# Copy application source
COPY app/ ./

# Change ownership to nodejs user
RUN chown -R nodejs:nodejs /app
USER nodejs

# Build the application
RUN npm run build

# Runtime stage
FROM node:20-slim AS runner

# Install security tools and system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    jq \
    gosu \
    ca-certificates \
    dumb-init \
    && curl -L https://foundry.paradigm.xyz | bash \
    && ~/.foundry/bin/foundryup \
    && ln -s ~/.foundry/bin/cast /usr/local/bin/cast \
    && ln -s ~/.foundry/bin/chisel /usr/local/bin/chisel \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/*

# Create non-root user for runtime
RUN groupadd --system --gid 1001 nodejs && \
    useradd --system --uid 1001 --gid nodejs --home /app nodejs

WORKDIR /app

# Copy built application from builder
COPY --from=builder --chown=nodejs:nodejs /app/.next ./.next
COPY --from=builder --chown=nodejs:nodejs /app/public ./public
COPY --from=builder --chown=nodejs:nodejs /app/package*.json ./
COPY --from=builder --chown=nodejs:nodejs /app/next.config.js ./

# Copy secure entrypoint and shell script
COPY --chown=nodejs:nodejs docker-entrypoint.sh /usr/local/bin/
COPY --chown=nodejs:nodejs safe_hashes.sh /
RUN chmod +x /usr/local/bin/docker-entrypoint.sh /safe_hashes.sh

# Security: Set environment variables
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV NPM_CONFIG_AUDIT=false
ENV NPM_CONFIG_FUND=false
ENV NODE_OPTIONS="--max-old-space-size=512 --no-warnings --disable-proto=delete --disallow-code-generation-from-strings --frozen-intrinsics"
ENV FORCE_COLOR=0
ENV NO_UPDATE_NOTIFIER=1

# Set proper ownership before installing production dependencies
RUN chown -R nodejs:nodejs /app

# Install ONLY production dependencies as nodejs user (ignore scripts for Docker)
USER nodejs
RUN npm ci --only=production --ignore-scripts && npm cache clean --force

# Security hardening: Remove sensitive files and set secure permissions
USER root
RUN apt-get update && apt-get remove -y npm && apt-get autoremove -y && apt-get clean && \
    rm -rf /usr/local/lib/node_modules/npm && \
    find /app -name "*.md" -type f -delete && \
    find /app -name "*.txt" -type f -delete && \
    find /app -name "test*" -type d -exec rm -rf {} + 2>/dev/null || true && \
    find /app -name "*.test.js" -type f -delete && \
    find /app -name "*.spec.js" -type f -delete && \
    chmod -R o-rwx /app && \
    chmod -R g-w /app

# Create required directories with secure permissions
RUN mkdir -p /app/logs /tmp/app && \
    chown nodejs:nodejs /app/logs /tmp/app && \
    chmod 750 /app/logs && \
    chmod 1777 /tmp/app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:3000/api/health || exit 1

# Expose port
EXPOSE 3000

# Security: Use dumb-init as PID 1 and secure entrypoint
ENTRYPOINT ["dumb-init", "--"]
CMD ["docker-entrypoint.sh"]
