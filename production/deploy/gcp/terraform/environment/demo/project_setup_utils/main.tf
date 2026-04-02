terraform {
  required_version = ">= 1.2.3"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "6.2.0"
    }
  }

  # TODO: Create this bucket first:
  #   gcloud storage buckets create gs://<YOUR_PROJECT_ID>-tfstate \
  #     --project=<YOUR_PROJECT_ID> --location=<YOUR_REGION>
  backend "gcs" {
    bucket = "<YOUR_PROJECT_ID>-tfstate"  # <-- CHANGE: GCS bucket for terraform state
    prefix = "terraform-state/project-setup"
  }
}

module "api" {
  source     = "./api"
  project_id = var.project_id
}

module "domain" {
  source     = "./domain"
  project_id = var.project_id
  domain     = var.domain
}

module "internal_tls" {
  source     = "./internal_tls"
  project_id = var.project_id
  depends_on = [module.api]
}

module "service_account" {
  source               = "./service_account"
  project_id           = var.project_id
  service_account_name = var.service_account_name
  depends_on = [module.api]
}
