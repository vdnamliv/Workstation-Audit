#!/bin/bash
# Pre-pull Docker Images
# Run this before docker compose up to avoid build issues
# Usage: bash pull-images.sh

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}VT-AUDIT Docker Image Puller${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Pull base images
echo -e "${YELLOW}[1/4]${NC} Pulling StepCA image..."
docker pull smallstep/step-ca:0.27.4

echo -e "${YELLOW}[2/4]${NC} Pulling PostgreSQL image..."
docker pull postgres:16.10-alpine

echo -e "${YELLOW}[3/4]${NC} Pulling Keycloak image..."
docker pull quay.io/keycloak/keycloak:25.0

echo -e "${YELLOW}[4/4]${NC} Pulling Nginx image..."
docker pull nginx:1.27-alpine

echo ""
echo -e "${GREEN}[SUCCESS]${NC} All images pulled successfully!"
echo ""
echo "Build images (optional):"
echo "  For Golang 1.25: docker pull golang:1.25-alpine"
echo "  For Distroless: docker pull gcr.io/distroless/static-debian12:latest"
