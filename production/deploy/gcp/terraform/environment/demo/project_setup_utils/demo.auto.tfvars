# TODO: Fill in all three values before running terraform apply.
project_id           = "<YOUR_PROJECT_ID>"       # GCP project ID (e.g. "my-project-123")
domain               = "<YOUR_DOMAIN>"           # Base domain you own (e.g. "buyer.example.com"). Creates bfe.* and sfe.* subzones.
service_account_name = "<SA_SHORT_NAME>"          # 6-30 chars, lowercase + hyphens only (e.g. "ba-services"). NOT a full email.
