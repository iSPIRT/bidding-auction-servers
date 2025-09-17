# GitHub Actions Security Configuration
# This file documents security best practices for the Azure CI/CD pipeline

## Secrets Management

### Required Repository Secrets
- `AZURE_CLIENT_ID`: Service principal client ID (UUID format)
- `AZURE_CLIENT_SECRET`: Service principal client secret (base64 string)
- `AZURE_TENANT_ID`: Azure Active Directory tenant ID (UUID format)
- `AZURE_SUBSCRIPTION_ID`: Azure subscription ID (UUID format)

### Required Repository Variables
- `AZURE_REGISTRY_NAME`: Azure Container Registry name (alphanumeric, no .azurecr.io suffix)

## Security Best Practices

### 1. Service Principal Configuration
- Use dedicated service principal for CI/CD
- Grant minimum required permissions (Contributor on ACR only)
- Rotate credentials regularly (every 90 days recommended)
- Enable conditional access policies if possible

### 2. Repository Security
- Enable branch protection on main branch
- Require pull request reviews before merging
- Require status checks to pass before merging
- Restrict push access to main branch

### 3. Workflow Security
- Use pinned action versions with SHA hashes
- Limit workflow permissions to minimum required
- Use `if` conditions to restrict when jobs run
- Validate inputs and environment variables

### 4. Container Security
- Enable vulnerability scanning on all images
- Use minimal base images (distroless when possible)
- Regularly update base images and dependencies
- Sign container images for supply chain security

### 5. Build Security
- Use deterministic builds where possible
- Enable Bazel's sandboxing features
- Scan dependencies for known vulnerabilities
- Generate and store Software Bill of Materials (SBOM)

## Incident Response

### If Credentials Are Compromised
1. Immediately rotate the compromised service principal credentials
2. Update GitHub repository secrets with new credentials
3. Review ACR access logs for unauthorized activity
4. Re-scan all recently published images
5. Consider rotating signing keys if image signing is enabled

### If Build Pipeline Is Compromised
1. Disable the GitHub Actions workflow
2. Review recent workflow runs for suspicious activity
3. Scan all recently built images
4. Update all dependencies and base images
5. Re-enable workflow after security review

## Compliance

### Audit Trail
- All build actions are logged in GitHub Actions
- Container pushes are logged in Azure Container Registry
- Access to secrets is logged by GitHub

### Data Residency
- Build artifacts are stored in GitHub (US-based)
- Container images are stored in configured Azure region
- Logs may be stored in multiple regions per service provider policies

### Access Control
- Repository access controlled by GitHub organization policies
- ACR access controlled by Azure RBAC
- Service principal follows principle of least privilege

## Monitoring

### Recommended Alerts
- Failed authentication to Azure Container Registry
- Unexpected image pushes or pulls
- Large number of vulnerability findings in scanned images
- Workflow failures or unusual execution patterns

### Metrics to Track
- Build success/failure rates
- Build duration trends
- Image vulnerability counts over time
- Credential usage patterns

## References
- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Azure Container Registry Security](https://docs.microsoft.com/en-us/azure/container-registry/container-registry-security)
- [Supply Chain Security Best Practices](https://slsa.dev/)