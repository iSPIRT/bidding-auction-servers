terraform {
  required_version = ">= 1.2.3"

  required_providers {
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "5.31.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "5.31.0"
    }
  }

  # Same bucket as project_setup, different prefix.
  backend "gcs" {
    bucket = "<YOUR_PROJECT_ID>-tfstate"  # <-- CHANGE: must match project_setup_utils/main.tf
    prefix = "terraform-state/buyer"
  }
}
