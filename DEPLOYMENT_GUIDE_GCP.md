# Buyer Stack (Bidding + BFE) — GCP Confidential Space Deployment Guide

## Prerequisites

- **GCP project** with billing enabled
- **Domain** you control (e.g. `buyer.example.com`)
- **Quotas**: `N2D_CPUS` ≥ 128 in your region, `CPUS_ALL_REGIONS` ≥ 140. Confidential VMs require N2D (AMD SEV) — other families (C2D, N2, E2) won't work.
- **Tools**: `gcloud` CLI, `terraform` ≥ 1.2.3
- **IAM**: `roles/owner` on the GCP project
- **Container images**: publicly pullable `bidding_service` and `buyer_frontend_service`

Check quotas:

```bash
gcloud compute regions describe <REGION> --project=<PROJECT_ID> --format=json \
  | python3 -c "import json,sys;[print(f\"{q['metric']:20s} {int(q['limit'])}\") for q in json.load(sys.stdin)['quotas'] if 'N2D' in q['metric'] or q['metric']=='CPUS']"
```

Request increases at https://console.cloud.google.com/iam-admin/quotas if needed.

### Private registries

If your images are in a private registry (e.g. Quay), mirror them to GCP Artifact Registry first — the service account already has `artifactregistry.reader`:

```bash
gcloud artifacts repositories create services --repository-format=docker \
  --location=<REGION> --project=<PROJECT_ID>

docker pull <private-registry>/bidding_service:<tag>
docker tag  <private-registry>/bidding_service:<tag> <REGION>-docker.pkg.dev/<PROJECT_ID>/services/bidding_service:<tag>
docker push <REGION>-docker.pkg.dev/<PROJECT_ID>/services/bidding_service:<tag>
# Repeat for buyer_frontend_service
```

Then use `<REGION>-docker.pkg.dev/<PROJECT_ID>/services` as your `image_repo`.

---

## Step 1 — Authenticate

```bash
gcloud auth login
gcloud config set project <YOUR_PROJECT_ID>
gcloud auth application-default login --scopes=https://www.googleapis.com/auth/cloud-platform
```

## Step 2 — Clone and create state bucket

```bash
git clone https://github.com/iSPIRT/bidding-auction-servers.git
cd bidding-auction-servers

gcloud storage buckets create gs://<YOUR_PROJECT_ID>-tfstate \
  --project=<YOUR_PROJECT_ID> --location=<YOUR_REGION>
```

## Step 3 — Project setup (APIs, DNS, TLS, service account)

Edit two files — search for `CHANGE` markers:

**`production/deploy/gcp/terraform/environment/demo/project_setup_utils/main.tf`** — set `bucket` in the backend block to your tfstate bucket name.

**`production/deploy/gcp/terraform/environment/demo/project_setup_utils/demo.auto.tfvars`** — set `project_id`, `domain`, and `service_account_name`.

Then apply:

```bash
cd production/deploy/gcp/terraform/environment/demo/project_setup_utils
terraform init
terraform plan      # Dry-run: verify config resolves with 0 errors
terraform apply     # Creates ~62 resources: APIs, DNS zones, TLS certs, service account
```

**Save the outputs** — you'll need them in Step 4:

```
bfe_dns_zone                = "..."
frontend_certificate_map_id = "..."
service_account_full_name   = "..."
zone_url                    = "..."
```

**Configure DNS delegation**: visit the `zone_url`, copy NS records, add them at your domain registrar. Required for TLS certificate provisioning.

## Step 4 — Deploy buyer stack (bidding + BFE)

Edit two files — search for `CHANGE` markers:

**`production/deploy/gcp/terraform/environment/demo/buyer/terraform.tf`** — set `bucket` to your tfstate bucket name.

**`production/deploy/gcp/terraform/environment/demo/buyer/buyer.tf`** — fill in all values marked `CHANGE` using the outputs from Step 3. Summary of what to set:

| Marker | Where | What to set |
|---|---|---|
| `gcp_project_id` | locals | Your GCP project ID |
| `environment` | locals | ≤ 3 char label (e.g. `"prd"`) |
| `image_repo` | locals | Registry base path (e.g. `"us-docker.pkg.dev/proj/services"`) |
| `<YOUR_REGION>` | default_region_config key | Region with N2D quota (e.g. `"asia-south1"`) |
| `frontend_certificate_map_id` | locals | `//certificatemanager.googleapis.com/` + output from Step 3 |
| `buyer_domain_name` | locals | `bfe.` + your domain |
| `frontend_dns_zone` | locals | `bfe_dns_zone` output from Step 3 |
| `<IMAGE_TAG>` | buyer_traffic_splits (3 places) | Your image tag (e.g. `"nonprod-4.8.0"`) |
| `<BIDDING_JS_URL>` | BUYER_CODE_FETCH_CONFIG | URL to your generateBid JS UDF |
| `<YOUR_DOMAIN>` | COLLECTOR_ENDPOINT | Your base domain |
| `service_account_email` | module "buyer" | `service_account_full_name` output from Step 3 |
| `gcs_bucket` | collector_startup_script | Your tfstate bucket name |

Then apply:

```bash
cd production/deploy/gcp/terraform/environment/demo/buyer
terraform init
terraform plan      # Dry-run: expect ~169 resources, 0 errors
terraform apply     # Takes ~10 minutes
```

On success:

```
buyer_frontend_url = "https://byr-<ENV>.bfe.<YOUR_DOMAIN>"
```

## Step 5 — Verify

```bash
# Instance groups — expect 3 MIGs (bfe, bidding, collector), all IS_STABLE=True
gcloud compute instance-groups managed list --project=<PROJECT_ID> \
  --format="table(name,region,size,status.isStable)"

# Check for creation errors
gcloud compute instance-groups managed list-errors <MIG_NAME> \
  --region=<REGION> --project=<PROJECT_ID>

# VM status — all should be RUNNING
gcloud compute instances list --project=<PROJECT_ID> \
  --format="table(name,zone,machineType.basename(),status)"

# Serial logs (debug image only)
gcloud compute instances get-serial-port-output <INSTANCE> \
  --zone=<ZONE> --project=<PROJECT_ID> | tail -50
```

## Tear down

```bash
cd production/deploy/gcp/terraform/environment/demo/buyer && terraform destroy
cd ../project_setup_utils && terraform destroy
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| MIG size=0, `QUOTA_EXCEEDED` | Request N2D_CPUS + CPUS_ALL_REGIONS quota increase |
| `bucket doesn't exist` on init | Create the GCS bucket (Step 2) |
| `already exists` (409) on apply | Delete conflicting resource or `terraform import` it |
| `payload required` on apply | A runtime flag is `""` — set to `"NONE"` instead |
| TLS cert stuck provisioning | Configure DNS delegation at your registrar (Step 3) |
| Health checks failing | Wait 3-5 min after apply (200s startup delay) |
| Image pull fails | Ensure registry is public, or mirror to GCP Artifact Registry |
