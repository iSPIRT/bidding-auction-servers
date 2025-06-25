# Azure Container Registry CI/CD Setup

This guide explains how to configure the GitHub Actions CI/CD pipeline to build and publish bidding-auction-servers images to Azure Container Registry (ACR).

## Prerequisites

### 1. Azure Container Registry

Create an Azure Container Registry if you don't have one:

```bash
# Create resource group (if needed)
az group create --name bidding-auction-rg --location eastus

# Create container registry
az acr create --resource-group bidding-auction-rg \
  --name biddingauction \
  --sku Basic \
  --admin-enabled true
```

### 2. Service Principal for Authentication

Create a service principal with access to your ACR:

```bash
# Get ACR registry ID
ACR_REGISTRY_ID=$(az acr show --name biddingauction --resource-group bidding-auction-rg --query id --output tsv)

# Create service principal with contributor role to ACR
az ad sp create-for-rbac \
  --name bidding-auction-ci \
  --role Contributor \
  --scopes $ACR_REGISTRY_ID \
  --sdk-auth
```

This command will output JSON credentials like:
```json
{
  "clientId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "clientSecret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "subscriptionId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "tenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

## GitHub Repository Configuration

### Required Secrets

Add the following secrets to your GitHub repository:

1. **AZURE_CLIENT_ID**: The `clientId` from service principal output
2. **AZURE_CLIENT_SECRET**: The `clientSecret` from service principal output
3. **AZURE_TENANT_ID**: The `tenantId` from service principal output
4. **AZURE_SUBSCRIPTION_ID**: The `subscriptionId` from service principal output

### Required Variables

Add the following repository variable:

1. **AZURE_REGISTRY_NAME**: Your ACR name (e.g., `biddingauction`)

### Setting Secrets and Variables

#### Via GitHub Web Interface:

1. Go to your repository → Settings → Secrets and variables → Actions
2. Add each secret under "Repository secrets"
3. Add variables under "Repository variables"

#### Via GitHub CLI:

```bash
# Set secrets
gh secret set AZURE_CLIENT_ID --body "your-client-id"
gh secret set AZURE_CLIENT_SECRET --body "your-client-secret"
gh secret set AZURE_TENANT_ID --body "your-tenant-id"
gh secret set AZURE_SUBSCRIPTION_ID --body "your-subscription-id"

# Set variables
gh variable set AZURE_REGISTRY_NAME --body "biddingauction"
```

## Pipeline Configuration

The CI/CD pipeline is configured in `.github/workflows/ci.yml` and includes:

### Build Triggers

- **Push to main branch**: Builds and pushes images with `latest` and commit SHA tags
- **Tagged releases**: Builds and pushes images with release tag and `latest`
- **Pull requests**: Runs tests only (no image publishing)

### Built Services

The pipeline builds Docker images for these services:
- `auction_service`
- `bidding_service` 
- `buyer_frontend_service`
- `seller_frontend_service`

### Image Tagging Strategy

Images are tagged with:
- Commit SHA: `{registry}/{service}:{commit_sha}`
- Git tags: `{registry}/{service}:{git_tag}-{build_flavor}`
- Latest (main branch): `{registry}/{service}:latest`
- Release tags: `{registry}/{service}:{release_version}`

## Usage Examples

### Pulling Images

After successful pipeline execution, pull images using:

```bash
# Login to ACR
az acr login --name biddingauction

# Pull latest images
docker pull biddingauction.azurecr.io/auction_service:latest
docker pull biddingauction.azurecr.io/bidding_service:latest
docker pull biddingauction.azurecr.io/buyer_frontend_service:latest
docker pull biddingauction.azurecr.io/seller_frontend_service:latest

# Pull specific version
docker pull biddingauction.azurecr.io/auction_service:v1.0.0
```

### Local Development

To test the build locally:

```bash
# Set environment variables
export AZURE_REGISTRY=biddingauction.azurecr.io
export AZURE_IMAGE_TAG=$(git rev-parse --short HEAD)
export AZURE_BUILD_FLAVOR=prod

# Login to Azure (one-time setup)
az login

# Run the build script
WORKSPACE_MOUNT=$(pwd) \
production/packaging/build_and_test_all_in_docker \
  --service-path buyer_frontend_service \
  --service-path seller_frontend_service \
  --service-path bidding_service \
  --service-path auction_service \
  --instance gcp --platform gcp \
  --build-flavor prod \
  --no-tests --no-precommit
```

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   - Verify service principal credentials are correct
   - Ensure service principal has Contributor access to ACR
   - Check that AZURE_REGISTRY_NAME variable matches your ACR name

2. **Build Failures**
   - Check Bazel cache permissions
   - Verify all required dependencies are available
   - Review build logs for specific error messages

3. **Image Push Failures**
   - Confirm ACR admin is enabled or service principal has push permissions
   - Verify registry name format: `{name}.azurecr.io`
   - Check network connectivity to Azure

### Debug Commands

```bash
# Test ACR connectivity
az acr check-health --name biddingauction

# List repositories in ACR  
az acr repository list --name biddingauction

# Show image tags
az acr repository show-tags --name biddingauction --repository auction_service

# Test Docker login
az acr login --name biddingauction
```

## Security Considerations

- Service principal follows principle of least privilege (Contributor access only to ACR)
- Secrets are stored securely in GitHub Actions encrypted storage
- Images are scanned for vulnerabilities using integrated security tools
- Build artifacts include SHA256 digests for integrity verification

## Performance Optimizations

The pipeline includes several optimizations:

1. **Bazel Caching**: Uses GitHub Actions cache to persist Bazel build cache
2. **Docker Layer Caching**: Leverages Docker Buildx for efficient layer caching
3. **Parallel Builds**: Test and build jobs can run in parallel for different services
4. **Incremental Builds**: Only rebuilds changed components using Bazel's dependency analysis

## Advanced Configuration

### Custom Build Flavors

To build with different flavors (e.g., `debug`):

```bash
export AZURE_BUILD_FLAVOR=debug
# Run build command
```

### Multi-Architecture Builds

For ARM64 support, the existing Bazel configuration supports multi-platform builds. The Docker images will be built for the appropriate architecture based on the build environment.

### Custom Registry

To use a different Azure Container Registry:

1. Update the `AZURE_REGISTRY_NAME` repository variable
2. Ensure service principal has access to the new registry
3. Update any hardcoded references in deployment scripts