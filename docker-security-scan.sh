#!/bin/bash

# Docker Security Scanning Script
# Comprehensive security analysis for Safe Utils container

set -euo pipefail

# Configuration
IMAGE_NAME="safe-utils"
TAG="${1:-latest}"
FULL_IMAGE_NAME="${IMAGE_NAME}:${TAG}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔍 Starting comprehensive security scan for ${FULL_IMAGE_NAME}${NC}"
echo "========================================================"

# Check if required tools are installed
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}❌ $1 is not installed. Please install it first.${NC}"
        return 1
    fi
    echo -e "${GREEN}✅ $1 is available${NC}"
}

echo -e "${BLUE}Checking security tools...${NC}"
check_tool "docker"
check_tool "trivy" || echo -e "${YELLOW}⚠️  Install trivy for vulnerability scanning: https://aquasecurity.github.io/trivy/v0.18.3/installation/${NC}"

# Build the image if it doesn't exist
if ! docker image inspect "$FULL_IMAGE_NAME" &> /dev/null; then
    echo -e "${YELLOW}📦 Building image ${FULL_IMAGE_NAME}...${NC}"
    docker build -t "$FULL_IMAGE_NAME" .
fi

echo -e "${BLUE}🏗️  Image Information${NC}"
echo "----------------------------------------"
docker image inspect "$FULL_IMAGE_NAME" --format='{{json .}}' | jq '{
    Id: .Id,
    Created: .Created,
    Size: .Size,
    Architecture: .Architecture,
    Os: .Os,
    RootFS: .RootFS.Type
}' 2>/dev/null || echo "Image: $FULL_IMAGE_NAME exists"

# Security scan with Trivy (if available)
if command -v trivy &> /dev/null; then
    echo -e "${BLUE}🔍 Running Trivy vulnerability scan...${NC}"
    echo "----------------------------------------"
    
    # Scan for vulnerabilities
    trivy image --severity HIGH,CRITICAL --format table "$FULL_IMAGE_NAME"
    
    # Generate JSON report
    trivy image --severity HIGH,CRITICAL --format json --output security-report.json "$FULL_IMAGE_NAME"
    
    # Check if any HIGH or CRITICAL vulnerabilities were found
    CRITICAL_COUNT=$(jq '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL") | .VulnerabilityID' security-report.json 2>/dev/null | wc -l || echo "0")
    HIGH_COUNT=$(jq '.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH") | .VulnerabilityID' security-report.json 2>/dev/null | wc -l || echo "0")
    
    echo "Critical vulnerabilities: $CRITICAL_COUNT"
    echo "High vulnerabilities: $HIGH_COUNT"
    
    if [ "$CRITICAL_COUNT" -gt 0 ]; then
        echo -e "${RED}❌ CRITICAL vulnerabilities found! Review security-report.json${NC}"
        exit 1
    elif [ "$HIGH_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}⚠️  HIGH severity vulnerabilities found. Consider updating dependencies.${NC}"
    else
        echo -e "${GREEN}✅ No HIGH or CRITICAL vulnerabilities found${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Trivy not available, skipping vulnerability scan${NC}"
fi

# Docker security best practices check
echo -e "${BLUE}🛡️  Security Best Practices Check${NC}"
echo "----------------------------------------"

# Check if running as non-root
USER_CHECK=$(docker image inspect "$FULL_IMAGE_NAME" --format='{{.Config.User}}')
if [ -n "$USER_CHECK" ] && [ "$USER_CHECK" != "root" ]; then
    echo -e "${GREEN}✅ Container runs as non-root user: $USER_CHECK${NC}"
else
    echo -e "${RED}❌ Container may be running as root${NC}"
fi

# Check for security labels
LABELS=$(docker image inspect "$FULL_IMAGE_NAME" --format='{{json .Config.Labels}}')
if echo "$LABELS" | jq -e '.maintainer' &> /dev/null; then
    echo -e "${GREEN}✅ Maintainer label present${NC}"
else
    echo -e "${YELLOW}⚠️  Missing maintainer label${NC}"
fi

# Check image size (smaller is better for security)
SIZE=$(docker image inspect "$FULL_IMAGE_NAME" --format='{{.Size}}')
SIZE_MB=$((SIZE / 1024 / 1024))
echo "Image size: ${SIZE_MB}MB"

if [ "$SIZE_MB" -lt 200 ]; then
    echo -e "${GREEN}✅ Good image size (< 200MB)${NC}"
elif [ "$SIZE_MB" -lt 500 ]; then
    echo -e "${YELLOW}⚠️  Moderate image size (${SIZE_MB}MB)${NC}"
else
    echo -e "${RED}❌ Large image size (${SIZE_MB}MB) - consider optimization${NC}"
fi

# Test container startup
echo -e "${BLUE}🚀 Testing container startup...${NC}"
echo "----------------------------------------"

CONTAINER_ID=$(docker run -d -p 3001:3000 --name "${IMAGE_NAME}-security-test" "$FULL_IMAGE_NAME")
sleep 10

# Check if container is running
if docker ps | grep -q "$CONTAINER_ID"; then
    echo -e "${GREEN}✅ Container started successfully${NC}"
    
    # Test health endpoint
    if curl -f -s http://localhost:3001/api/health > /dev/null; then
        echo -e "${GREEN}✅ Health check endpoint responding${NC}"
    else
        echo -e "${YELLOW}⚠️  Health check endpoint not responding${NC}"
    fi
    
    # Check for any running processes as root
    ROOT_PROCESSES=$(docker exec "$CONTAINER_ID" ps aux 2>/dev/null | grep -c "^root" || echo "0")
    if [ "$ROOT_PROCESSES" -eq 0 ]; then
        echo -e "${GREEN}✅ No processes running as root${NC}"
    else
        echo -e "${YELLOW}⚠️  $ROOT_PROCESSES processes running as root${NC}"
    fi
    
else
    echo -e "${RED}❌ Container failed to start${NC}"
    docker logs "$CONTAINER_ID"
fi

# Cleanup
docker stop "$CONTAINER_ID" &> /dev/null || true
docker rm "$CONTAINER_ID" &> /dev/null || true

# Security recommendations
echo -e "${BLUE}📋 Security Recommendations${NC}"
echo "----------------------------------------"
echo -e "${GREEN}✅ Use distroless or minimal base images${NC}"
echo -e "${GREEN}✅ Run as non-root user${NC}"
echo -e "${GREEN}✅ Keep dependencies updated${NC}"
echo -e "${GREEN}✅ Use specific image tags, not 'latest'${NC}"
echo -e "${GREEN}✅ Implement health checks${NC}"
echo -e "${GREEN}✅ Use .dockerignore to exclude sensitive files${NC}"
echo -e "${GREEN}✅ Scan regularly for vulnerabilities${NC}"

echo ""
echo -e "${BLUE}🎉 Security scan completed!${NC}"

# Return appropriate exit code
if [ "$CRITICAL_COUNT" -gt 0 ] 2>/dev/null; then
    exit 1
else
    exit 0
fi