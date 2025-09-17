# Privacy Sandbox - Bidding and Auction service

The current codebase represents the implementation and setup of the Bidding and Auction servers.
Learn more about these servers:

-   [bidding and auction services](https://github.com/privacysandbox/fledge-docs#bidding-and-auction-services)
-   [bidding and auction server productionization](https://github.com/privacysandbox/fledge-docs#server-productionization)

## CI/CD and Build System

This repository includes comprehensive CI/CD pipelines for building and deploying the bidding and auction services:

### Azure Container Registry Pipeline

The main CI/CD pipeline builds Docker images and publishes them to Azure Container Registry (ACR):

- **Automated builds**: Triggered on push to main branch and pull requests
- **Multi-service support**: Builds auction_service, bidding_service, buyer_frontend_service, seller_frontend_service
- **Intelligent tagging**: Uses commit SHA, git tags, and latest tags
- **Security scanning**: Integrated vulnerability scanning for container images
- **Bazel optimization**: Persistent caching for faster build times

[Setup Guide](production/packaging/azure/README.md) | [Workflow File](.github/workflows/ci.yml)

### Other Supported Platforms

- **AWS CodeBuild**: [Setup instructions](production/packaging/aws/codebuild/README.md)
- **GCP Cloud Build**: [Setup instructions](production/packaging/gcp/cloud_build/README.md)

### Local Development

Build all services locally using the provided script:

```bash
production/packaging/build_and_test_all_in_docker \
  --service-path buyer_frontend_service \
  --service-path seller_frontend_service \
  --service-path bidding_service \
  --service-path auction_service \
  --instance gcp --platform gcp \
  --build-flavor prod
```

---

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/privacysandbox/bidding-auction-servers/badge)](https://securityscorecards.dev/viewer/?uri=github.com/privacysandbox/bidding-auction-servers)
