#!/bin/bash
set -e

# Define script directory and paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../" && pwd)"
BAZEL_BIN_DIR="${PROJECT_ROOT}/bazel-bin"
IMAGE_NAME="secure_invoke"
IMAGE_TAG="latest"

echo $SCRIPT_DIR, $PROJECT_ROOT, $BAZEL_BIN_DIR

echo "Creating Docker image for secure_invoke..."

# First, make sure the binary is built
echo "Building secure_invoke binary with Bazel..."
cd "${PROJECT_ROOT}"
./builders/tools/bazel-debian build //tools/secure_invoke:invoke

#copy entrypoint.sh to bazel-bin to access from Dockerfile
cp "${PROJECT_ROOT}/tools/secure_invoke/entrypoint.sh" "${BAZEL_BIN_DIR}/tools/secure_invoke/entrypoint.sh"

echo "Building Docker image..."
cd "${BAZEL_BIN_DIR}"
docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" -f ${PROJECT_ROOT}/tools/secure_invoke/Dockerfile .

echo "Docker image ${IMAGE_NAME}:${IMAGE_TAG} built successfully!"
echo ""
echo "You can run it with:"
echo "docker run --rm --network host -v /path/to/input-files:/data ${IMAGE_NAME}:${IMAGE_TAG} -target_service=bfe -input_file=/data/input.json -host_addr=localhost:50051 -client_ip=127.0.0.1 -insecure"