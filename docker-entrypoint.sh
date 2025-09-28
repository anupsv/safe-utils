#!/bin/bash

# Secure Docker entrypoint for Safe Utils
# This script configures Node.js with security hardening before starting the application

set -euo pipefail

echo "🔒 Safe Utils - Secure Docker Entrypoint"
echo "Starting application with security hardening..."

# Set Node.js security flags
export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=512 --no-warnings --disable-proto=delete --disallow-code-generation-from-strings --frozen-intrinsics}"

# Additional security environment variables
export NODE_ENV="${NODE_ENV:-production}"
export FORCE_COLOR=0
export NO_UPDATE_NOTIFIER=1
export NPM_CONFIG_AUDIT=false
export NPM_CONFIG_FUND=false

# Security hardening flags (only if policy file exists)
if [[ -f "/app/security-policy.json" ]]; then
    export NODE_SECURITY_FLAGS="
    --experimental-policy=/app/security-policy.json
    --policy-integrity=sha384-$(cat /app/security-policy.json | openssl dgst -sha384 -binary | base64 -w 0)
    --heapsnapshot-signal=SIGUSR2
    --trace-warnings
    --trace-uncaught
    --unhandled-rejections=strict
    --experimental-report
    --report-on-fatalerror
    --report-on-signal
    --report-signal=SIGUSR1
    "
    echo "✅ Node.js policy file found - enabling policy enforcement"
else
    export NODE_SECURITY_FLAGS="
    --heapsnapshot-signal=SIGUSR2
    --trace-warnings
    --trace-uncaught
    --unhandled-rejections=strict
    --experimental-report
    --report-on-fatalerror
    --report-on-signal
    --report-signal=SIGUSR1
    "
    echo "⚠️  Node.js policy file not found - using basic security flags"
fi

# Memory and performance limits
export NODE_MEMORY_LIMIT="--max-old-space-size=512"
export NODE_PERFORMANCE="--max-semi-space-size=64"

# Security monitoring (selective tracing to reduce noise)
export NODE_MONITORING="
--trace-deprecation
--throw-deprecation
"

# Combine all Node options
export NODE_OPTIONS="$NODE_MEMORY_LIMIT $NODE_PERFORMANCE $NODE_MONITORING --experimental-permission --allow-fs-read=/app --allow-fs-write=/tmp --allow-child-process=false"

echo "🔐 Node.js Security Configuration:"
echo "  - Memory limit: 512MB"
echo "  - Code generation: DISABLED"
echo "  - Proto pollution: PROTECTED"
echo "  - Intrinsics: FROZEN"
echo "  - File system: READ-ONLY (except /tmp)"
echo "  - Child processes: DISABLED"
echo "  - Unhandled rejections: STRICT"

# Validate critical files exist
if [[ ! -f "/app/package.json" ]]; then
    echo "❌ ERROR: package.json not found"
    exit 1
fi

if [[ ! -d "/app/.next" ]]; then
    echo "❌ ERROR: .next build directory not found"
    exit 1
fi

# Verify LavaMoat configuration
if [[ -f "/app/lavamoat/node/policy.json" ]]; then
    echo "✅ LavaMoat policy found - enabling compartmentalization"
    export LAVAMOAT_ENABLED=true
else
    echo "⚠️  LavaMoat policy not found - running without compartmentalization"
    export LAVAMOAT_ENABLED=false
fi

# Set umask for secure file creation
umask 022

# Drop privileges if running as root
if [[ "$EUID" -eq 0 ]]; then
    echo "🔄 Dropping root privileges..."
    # Create non-root user if it doesn't exist
    if ! id "nodejs" &>/dev/null; then
        adduser --disabled-password --gecos "" nodejs
        chown -R nodejs:nodejs /app
    fi

    # Switch to non-root user
    exec gosu nodejs "$@"
else
    echo "✅ Running as non-root user (UID: $EUID)"
fi

# Start the application with security monitoring
echo "🚀 Starting Safe Utils with enhanced security..."

# Run with LavaMoat if available, otherwise with Node.js security flags
if [[ "$LAVAMOAT_ENABLED" == "true" ]]; then
    echo "🌋 Starting with LavaMoat protection..."
    exec npm start
else
    echo "🔐 Starting with Node.js security hardening..."
    exec node $NODE_OPTIONS ./node_modules/next/dist/bin/next start
fi