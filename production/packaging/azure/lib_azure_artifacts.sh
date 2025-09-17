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

#######################################
# Copy build artifacts to the workspace's dist/azure.
# Arguments:
#   * the docker image tar URI
# Globals:
#   WORKSPACE
#######################################
function create_azure_dist() {
  local -r server_image="$1"
  local -r dist_dir="${WORKSPACE}/dist"
  mkdir -p "${dist_dir}"/azure
  chmod 770 "${dist_dir}" "${dist_dir}"/azure
  cp "${WORKSPACE}/${server_image}" "${dist_dir}"/azure
}

#######################################
# Upload image to Azure Container Registry using Azure CLI.
# This function expects Azure authentication to be configured via:
# - Service Principal with AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID
# - Or Azure CLI login (az login)
# Arguments:
#   * the name of the service
#   * the docker image tar URI
#   * the azure container registry name
#   * the azure image tag  
#   * the build flavor
# Globals:
#   WORKSPACE
#   AZURE_REGISTRY (optional) - ACR registry name
#   AZURE_IMAGE_TAG (optional) - specific tag for the build
#######################################
function upload_image_to_azure_registry() {
  local -r service="$1"
  local -r server_image="$2"
  local -r azure_registry="$3"
  local -r azure_image_tag="$4"
  local -r build_flavor="$5"

  local -r local_image_uri=bazel/production/packaging/gcp/${service}:server_docker_image
  local -r repo_image_uri="${azure_registry}/${service}"
  local -r commit_tag="${repo_image_uri}:${azure_image_tag}"
  local -r git_tag="${repo_image_uri}:$(git -C "${WORKSPACE}" describe --tags --always || echo no-git-version)-${build_flavor}"

  printf "==== Uploading local image to Azure Container Registry %s =====\n" "${azure_registry}"
  
  # Load the Docker image from tar
  docker load -i "${WORKSPACE}/${server_image}"

  # Determine image tags to apply
  local -a image_tags=("${commit_tag}")
  
  # Add git-based tag
  if [[ "${git_tag}" != "${commit_tag}" ]]; then
    image_tags+=("${git_tag}")
  fi
  
  # Add latest tag for main branch builds
  if [[ -n "${GITHUB_REF}" && "${GITHUB_REF}" == "refs/heads/main" ]]; then
    local -r latest_tag="${repo_image_uri}:latest"
    image_tags+=("${latest_tag}")
  fi
  
  # Add release tag for tagged builds
  if [[ -n "${GITHUB_REF_TYPE}" && "${GITHUB_REF_TYPE}" == "tag" && -n "${GITHUB_REF_NAME}" ]]; then
    local -r release_tag="${repo_image_uri}:${GITHUB_REF_NAME}"
    image_tags+=("${release_tag}")
  fi

  # Tag and push each image
  for tag in "${image_tags[@]}"; do
    echo "Tagging and pushing: ${tag}"
    docker tag "${local_image_uri}" "${tag}"
    docker push "${tag}"
  done

  # Get the image digest and save it
  # Fetched format from docker inspect is: <repo url>@sha256:<64 char hash>
  # Saved format after cut is: sha256:<64 char hash>.
  local -r digest="$(docker inspect --format='{{index .RepoDigests 0}}' "${local_image_uri}" | cut -d '@' -f 2)"
  if [[ -n "${digest}" ]]; then
    mkdir -p "${WORKSPACE}"/dist/azure
    echo "${digest}" > "${WORKSPACE}"/dist/azure/"${service}"_"${build_flavor}".sha256
    echo "Image digest saved: ${digest}"
  fi
  
  printf "==== Successfully uploaded %s to Azure Container Registry =====\n" "${service}"
}

#######################################
# Build service for Azure Container Registry.
# This function loads the service image and calls upload function.
# Arguments:
#   * the name of the service
# Globals:
#   WORKSPACE
#   AZURE_REGISTRY
#   AZURE_IMAGE_TAG
#   AZURE_BUILD_FLAVOR
#######################################
function build_service_for_azure() {
  local -r service="$1"
  local -r docker_image=dist/debian/${service}_image.tar
  
  if ! [[ -s ${WORKSPACE}/${docker_image} ]]; then
    printf "Error: docker image tar file not found: %s\n" "${docker_image}" &>/dev/stderr
    return 1
  fi

  # Use environment variables or defaults
  local -r registry="${AZURE_REGISTRY:-}"
  local -r image_tag="${AZURE_IMAGE_TAG:-$(git -C "${WORKSPACE}" rev-parse --short HEAD)}"
  local -r build_flavor="${AZURE_BUILD_FLAVOR:-prod}"
  
  if [[ -z "${registry}" ]]; then
    printf "Error: AZURE_REGISTRY environment variable must be set\n" &>/dev/stderr
    return 1
  fi

  create_azure_dist "${docker_image}"
  
  # Check if we should skip upload (for testing)
  if [[ "${AZURE_SKIP_IMAGE_UPLOAD:-0}" -eq 1 ]]; then
    printf "==== Skipping Azure registry image upload. No image_digest will be recorded. =====\n"
    return 0
  fi
  
  upload_image_to_azure_registry \
    "${service}" \
    "${docker_image}" \
    "${registry}" \
    "${image_tag}" \
    "${build_flavor}"
}

#######################################
# Load service image from tar file without uploading.
# Arguments:
#   * the name of the service  
# Globals:
#   WORKSPACE
#######################################
function load_service_image_azure() {
  local -r service="$1"
  local -r docker_image=dist/debian/${service}_image.tar
  
  if ! [[ -s ${WORKSPACE}/${docker_image} ]]; then
    printf "Error: docker image tar file not found: %s\n" "${docker_image}" &>/dev/stderr
    return 1
  fi

  docker load -i "${WORKSPACE}/${docker_image}"
}