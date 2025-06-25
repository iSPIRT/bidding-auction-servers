#!/bin/bash
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Example script for local development and testing of Azure CI/CD pipeline

set -euo pipefail

# Configuration
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
WORKSPACE_ROOT="${SCRIPT_DIR}/../../.."

# Default values
AZURE_REGISTRY="${AZURE_REGISTRY:-example.azurecr.io}"
BUILD_FLAVOR="${BUILD_FLAVOR:-prod}"
SKIP_UPLOAD="${AZURE_SKIP_IMAGE_UPLOAD:-1}"
SERVICES="${SERVICES:-auction_service bidding_service}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

function log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

function log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

function log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

function print_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Local development script for Azure CI/CD pipeline testing.

OPTIONS:
    -r, --registry      Azure Container Registry name (default: ${AZURE_REGISTRY})
    -f, --flavor        Build flavor: prod, debug (default: ${BUILD_FLAVOR})
    -s, --services      Space-separated list of services to build (default: ${SERVICES})
    -u, --upload        Enable image upload (default: disabled for safety)
    -h, --help          Show this help message

EXAMPLES:
    # Test build without uploading
    $0 --registry myregistry.azurecr.io --services "auction_service"
    
    # Build and upload (requires Azure login)
    az login
    $0 --registry myregistry.azurecr.io --upload
    
    # Build all services with debug flavor
    $0 --flavor debug --services "auction_service bidding_service buyer_frontend_service seller_frontend_service"

ENVIRONMENT VARIABLES:
    AZURE_REGISTRY              Azure Container Registry
    BUILD_FLAVOR                Build flavor (prod, debug)
    AZURE_SKIP_IMAGE_UPLOAD     Set to 0 to enable upload
    SERVICES                    Services to build
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--registry)
            AZURE_REGISTRY="$2"
            shift 2
            ;;
        -f|--flavor)
            BUILD_FLAVOR="$2"
            shift 2
            ;;
        -s|--services)
            SERVICES="$2"
            shift 2
            ;;
        -u|--upload)
            SKIP_UPLOAD=0
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Change to workspace root
cd "${WORKSPACE_ROOT}"

log_info "Starting local Azure CI/CD pipeline test"
log_info "Registry: ${AZURE_REGISTRY}"
log_info "Build flavor: ${BUILD_FLAVOR}"
log_info "Services: ${SERVICES}"
log_info "Upload enabled: $([[ ${SKIP_UPLOAD} -eq 0 ]] && echo "yes" || echo "no")"

# Check prerequisites
log_info "Checking prerequisites..."

if ! command -v docker >/dev/null 2>&1; then
    log_error "Docker is required but not installed"
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    log_error "Docker daemon is not running"
    exit 1
fi

if [[ ${SKIP_UPLOAD} -eq 0 ]]; then
    if ! command -v az >/dev/null 2>&1; then
        log_error "Azure CLI is required for upload but not installed"
        exit 1
    fi
    
    if ! az account show >/dev/null 2>&1; then
        log_error "Not logged into Azure. Run 'az login' first"
        exit 1
    fi
    
    log_info "Testing ACR connectivity..."
    if ! az acr check-health --name "${AZURE_REGISTRY%%.azurecr.io}" >/dev/null 2>&1; then
        log_warn "Cannot connect to ACR or ACR not found. Upload may fail."
    fi
fi

# Set environment variables
export AZURE_REGISTRY
export AZURE_IMAGE_TAG="${AZURE_IMAGE_TAG:-$(git rev-parse --short HEAD)}"
export AZURE_BUILD_FLAVOR="${BUILD_FLAVOR}"
export AZURE_SKIP_IMAGE_UPLOAD="${SKIP_UPLOAD}"
export WORKSPACE="${WORKSPACE_ROOT}"

log_info "Environment configured:"
log_info "  AZURE_REGISTRY: ${AZURE_REGISTRY}"
log_info "  AZURE_IMAGE_TAG: ${AZURE_IMAGE_TAG}"
log_info "  AZURE_BUILD_FLAVOR: ${AZURE_BUILD_FLAVOR}"

# Import CI configuration
if [[ -f ".bazelrc.ci" ]]; then
    log_info "Importing CI Bazel configuration..."
    echo "import %workspace%/.bazelrc.ci" >> .bazelrc.local
    trap "rm -f .bazelrc.local" EXIT
fi

# Build services
log_info "Building services: ${SERVICES}"

# Convert services string to array for build script
service_args=()
for service in ${SERVICES}; do
    service_args+=(--service-path "${service}")
done

# Run the build
WORKSPACE_MOUNT="${WORKSPACE_ROOT}" \
BAZEL_EXTRA_ARGS="--config=azure-ci" \
production/packaging/build_and_test_all_in_docker \
  "${service_args[@]}" \
  --instance gcp --platform gcp \
  --build-flavor "${BUILD_FLAVOR}" \
  --no-tests --no-precommit --no-platform-build

if [[ $? -eq 0 ]]; then
    log_info "Build completed successfully"
else
    log_error "Build failed"
    exit 1
fi

# Process built images
log_info "Processing built images..."
source production/packaging/azure/lib_azure_artifacts.sh

for service in ${SERVICES}; do
    image_tar="dist/debian/${service}_image.tar"
    if [[ -f "${image_tar}" ]]; then
        log_info "Processing ${service} image..."
        
        if [[ ${SKIP_UPLOAD} -eq 0 ]]; then
            build_service_for_azure "${service}"
        else
            load_service_image_azure "${service}"
            log_info "Image loaded locally (upload skipped): ${service}"
        fi
    else
        log_warn "Image not found for service: ${service}"
    fi
done

# Show results
log_info "Build artifacts:"
if [[ -d "dist" ]]; then
    ls -lhR dist/
else
    log_warn "No dist directory found"
fi

log_info "Docker images:"
docker images | grep -E "(bazel|${AZURE_REGISTRY})" || log_info "No matching images found"

log_info "Local test completed successfully!"

if [[ ${SKIP_UPLOAD} -eq 1 ]]; then
    log_info "To test with actual upload:"
    log_info "  az login"
    log_info "  $0 --registry ${AZURE_REGISTRY} --upload"
fi