# ==============================================================================
# Buyer Stack Configuration
#
# Search for "CHANGE" to find all values you need to set.
# Search for "OPTIONAL" for values you may want to customize.
# All other values are working defaults — do not change unless you know why.
# ==============================================================================

locals {
  # ---- Core identifiers (CHANGE all four) ----
  gcp_project_id = "<YOUR_PROJECT_ID>"    # CHANGE: GCP project ID
  environment    = "<ENV>"                 # CHANGE: ≤ 3 chars (e.g. "prd", "stg", "ci")
  image_repo     = "<YOUR_REGISTRY>"       # CHANGE: container registry base path (e.g. "us-docker.pkg.dev/my-project/services")
  buyer_operator = "byr"

  # ---- Region and machine config (CHANGE region, OPTIONAL machine sizes) ----
  # Machine type MUST be n2d-* for Confidential VMs (AMD SEV).
  # Verify you have N2D_CPUS quota in this region before applying.
  default_region_config = {
    "<YOUR_REGION>" = {                    # CHANGE: e.g. "asia-south1", "us-central1"
      collector = {
        machine_type          = "e2-micro"
        min_replicas          = 1
        max_replicas          = 1
        zones                 = null # Null signifies no zone preference.
        max_rate_per_instance = null # Null signifies no max.
      }
      backend = {
        machine_type          = "n2d-standard-64"
        min_replicas          = 1
        max_replicas          = 5
        zones                 = null # Null signifies no zone preference.
        max_rate_per_instance = null # Null signifies no max.
      }
      frontend = {
        machine_type          = "n2d-standard-64"
        min_replicas          = 1
        max_replicas          = 2
        zones                 = null # Null signifies no zone preference.
        max_rate_per_instance = null # Null signifies no max.
      }
    }
  }

  # ---- Domain and TLS (CHANGE — use outputs from project_setup terraform) ----
  # After running project_setup, run: terraform output
  # Then fill these in from those outputs.
  frontend_domain_ssl_certificate_id = ""
  frontend_certificate_map_id        = "//certificatemanager.googleapis.com/<frontend_certificate_map_id>"  # CHANGE: prepend //certificatemanager.googleapis.com/ to the output value
  buyer_domain_name                  = "bfe.<YOUR_DOMAIN>"        # CHANGE: "bfe." + your domain from project_setup
  frontend_dns_zone                  = "<bfe_dns_zone>"           # CHANGE: bfe_dns_zone output from project_setup

  # ---- Traffic config (CHANGE image_tag) ----
  buyer_traffic_splits = {
    "${local.environment}" = {
      image_tag             = "<IMAGE_TAG>"  # CHANGE: e.g. "nonprod-4.8.0"
      traffic_weight        = 1000 # traffic_weight for this arm, between 0~1000. default's weight must > 0.
      region_config         = local.default_region_config
      runtime_flag_override = {}
    }
    "${local.environment}-1" = {
      image_tag      = "<IMAGE_TAG>"         # CHANGE: same tag as above
      traffic_weight = 0                     # Weight 0 = inactive. Increase to enable experiment arm.
      region_config  = local.default_region_config
      runtime_flag_override = {}
    }
  }

  buyer_header_experiment = {
    "${local.environment}-h1" = {
      image_tag     = "<IMAGE_TAG>"          # CHANGE: same tag as above
      region_config = local.default_region_config
      runtime_flag_override = {}
      match_rules = []                       # Empty = inactive
    }
  }
}

provider "google" {
  project = local.gcp_project_id
}

provider "google-beta" {
  project = local.gcp_project_id
}

resource "google_compute_project_metadata" "default" {
  project = local.gcp_project_id
  metadata = {
    enable-oslogin = "FALSE"
  }
}

# See README.md for instructions on how to use the secrets module.
module "secrets" {
  source = "../../../modules/secrets"
}

module "buyer" {
  for_each = merge(
    { for key, value in local.buyer_traffic_splits :
    key => value if value.traffic_weight > 0 },
    { for key, value in local.buyer_header_experiment :
    key => value if length(value.match_rules) > 0 }
  )

  source               = "../../../modules/buyer"
  environment          = each.key
  gcp_project_id       = local.gcp_project_id
  bidding_image        = "${local.image_repo}/bidding_service:${each.value.image_tag}"
  buyer_frontend_image = "${local.image_repo}/buyer_frontend_service:${each.value.image_tag}"

  runtime_flags = merge({
    BIDDING_PORT                      = "50051"          # Do not change unless you are modifying the default GCP architecture.
    BUYER_FRONTEND_PORT               = "50051"          # Do not change unless you are modifying the default GCP architecture.
    BUYER_FRONTEND_HEALTHCHECK_PORT   = "50050"          # Do not change unless you are modifying the default GCP architecture.
    BIDDING_SERVER_ADDR               = "xds:///bidding" # Do not change unless you are modifying the default GCP architecture.
    BFE_INGRESS_TLS                   = "true"           # Do not change unless you are modifying the default GCP architecture.
    BIDDING_EGRESS_TLS                = "false"          # Do not change unless you are modifying the default GCP architecture.
    AD_RETRIEVAL_KV_SERVER_EGRESS_TLS = "false"          # Do not change unless you are modifying the default GCP architecture.
    KV_SERVER_EGRESS_TLS              = "false"          # Do not change unless you are modifying the default GCP architecture.
    TEST_MODE                         = "false"          # Do not change unless you are testing without key fetching.

    ENABLE_BIDDING_SERVICE_BENCHMARK = "false"

    # ---- KV Server config ----
    BUYER_KV_SERVER_ADDR = "NONE"           # OPTIONAL: set to real address if using BYOS KV server (e.g. "https://kvserver.com/trusted-signals")

    ENABLE_TKV_V2_BROWSER    = "true"
    TKV_EGRESS_TLS           = "false"
    BUYER_TKV_V2_SERVER_ADDR = "xds:///kv-service-host"

    # ---- Protected App Signals (leave defaults if not using PAS) ----
    TEE_AD_RETRIEVAL_KV_SERVER_ADDR = "NONE"  # OPTIONAL: set if using PAS ad retrieval (e.g. "xds:///ad-retrieval-host")
    TEE_KV_SERVER_ADDR              = "xds:///kv-service-host"
    AD_RETRIEVAL_TIMEOUT_MS         = "60000"

    # ---- Timeouts and features ----
    GENERATE_BID_TIMEOUT_MS            = "60000"
    BIDDING_SIGNALS_LOAD_TIMEOUT_MS    = "60000"
    ENABLE_BUYER_FRONTEND_BENCHMARKING = "false"
    CREATE_NEW_EVENT_ENGINE            = "false"
    ENABLE_BIDDING_COMPRESSION         = "false"
    ENABLE_PROTECTED_AUDIENCE          = "true"
    PS_VERBOSITY                       = "10"    # OPTIONAL: 0-10, lower for production

    ENABLE_PROTECTED_APP_SIGNALS                  = "false"
    PROTECTED_APP_SIGNALS_GENERATE_BID_TIMEOUT_MS = "60000"
    EGRESS_SCHEMA_FETCH_CONFIG = jsonencode({
      fetchMode         = 0
      egressSchemaUrl   = ""
      urlFetchPeriodMs  = 130000
      urlFetchTimeoutMs = 30000
    })

    # ---- Bidding UDF (CHANGE biddingJsUrl) ----
    BUYER_CODE_FETCH_CONFIG = jsonencode({
      fetchMode                               = 0
      biddingJsPath                           = ""
      biddingJsUrl                            = "<BIDDING_JS_URL>"  # CHANGE: URL to your generateBid JS
      protectedAppSignalsBiddingJsUrl         = ""
      biddingWasmHelperUrl                    = ""
      protectedAppSignalsBiddingWasmHelperUrl  = ""
      urlFetchPeriodMs                        = 13000000
      urlFetchTimeoutMs                       = 30000
      enableBuyerDebugUrlGeneration           = true
      prepareDataForAdsRetrievalJsUrl         = ""
      prepareDataForAdsRetrievalWasmHelperUrl  = ""
      enablePrivateAggregateReporting         = false
    })

    # ---- Worker config ----
    UDF_NUM_WORKERS           = "4"    # OPTIONAL: must be ≤ vCPUs in backend machine_type
    JS_WORKER_QUEUE_LEN       = "100"
    ROMA_TIMEOUT_MS           = "10000"

    # ---- Telemetry (CHANGE collector endpoint domain) ----
    TELEMETRY_CONFIG          = "mode: EXPERIMENT"
    COLLECTOR_ENDPOINT        = "collector-byr-${each.key}.bfe.<YOUR_DOMAIN>:4317"  # CHANGE: replace <YOUR_DOMAIN>
    ENABLE_OTEL_BASED_LOGGING = "true"
    CONSENTED_DEBUG_TOKEN     = "test-token"   # OPTIONAL: unique token for consented debugging
    DEBUG_SAMPLE_RATE_MICRO   = "0"

    # ---- Coordinator attestation (working defaults for Privacy Sandbox) ----
    # Do NOT change these unless using a custom KMS deployment.
    PUBLIC_KEY_ENDPOINT                           = "https://publickeyservice.pa.gcp.privacysandboxservices.com/.well-known/protected-auction/v1/public-keys"
    PRIMARY_COORDINATOR_PRIVATE_KEY_ENDPOINT      = "https://privatekeyservice-a.pa-3.gcp.privacysandboxservices.com/v1alpha/encryptionKeys"
    SECONDARY_COORDINATOR_PRIVATE_KEY_ENDPOINT    = "https://privatekeyservice-b.pa-4.gcp.privacysandboxservices.com/v1alpha/encryptionKeys"
    PRIMARY_COORDINATOR_ACCOUNT_IDENTITY          = "a-opverifiedusr@ps-pa-coord-prd-g3p-wif.iam.gserviceaccount.com"
    SECONDARY_COORDINATOR_ACCOUNT_IDENTITY        = "b-opverifiedusr@ps-prod-pa-type2-fe82.iam.gserviceaccount.com"
    PRIMARY_COORDINATOR_REGION                    = "us-central1"
    SECONDARY_COORDINATOR_REGION                  = "us-central1"
    GCP_PRIMARY_WORKLOAD_IDENTITY_POOL_PROVIDER   = "projects/732552956908/locations/global/workloadIdentityPools/a-opwip/providers/a-opwip-pvdr"
    GCP_SECONDARY_WORKLOAD_IDENTITY_POOL_PROVIDER = "projects/99438709206/locations/global/workloadIdentityPools/b-opwip/providers/b-opwip-pvdr"
    GCP_PRIMARY_KEY_SERVICE_CLOUD_FUNCTION_URL    = "https://a-us-central1-encryption-key-service-cloudfunctio-j27wiaaz5q-uc.a.run.app"
    GCP_SECONDARY_KEY_SERVICE_CLOUD_FUNCTION_URL  = "https://b-us-central1-encryption-key-service-cloudfunctio-wdqaqbifva-uc.a.run.app"
    PRIVATE_KEY_CACHE_TTL_SECONDS                 = "3974400"
    KEY_REFRESH_FLOW_RUN_FREQUENCY_SECONDS        = "20000"

    # ---- TLS (auto-populated from secrets module) ----
    BFE_TLS_KEY  = module.secrets.tls_key
    BFE_TLS_CERT = module.secrets.tls_cert
    MAX_ALLOWED_SIZE_DEBUG_URL_BYTES   = "65536"
    MAX_ALLOWED_SIZE_ALL_DEBUG_URLS_KB = "3000"

    # ---- Inference sidecar (OPTIONAL — set bucket if using inference) ----
    INFERENCE_SIDECAR_BINARY_PATH   = "/server/bin/inference_sidecar_tensorflow_v2_14_0"
    INFERENCE_MODEL_BUCKET_NAME     = "NONE"       # OPTIONAL: GCS bucket with your model, or "NONE" to skip
    INFERENCE_MODEL_CONFIG_PATH     = "model_config.json"
    INFERENCE_MODEL_FETCH_PERIOD_MS = "300000"
    INFERENCE_SIDECAR_RUNTIME_CONFIG = jsonencode({
      num_interop_threads = 4
      num_intraop_threads = 4
      module_name         = "tensorflow_v2_14_0"
    })

    # ---- TCMalloc (working defaults) ----
    BIDDING_TCMALLOC_BACKGROUND_RELEASE_RATE_BYTES_PER_SECOND = "4096"
    BIDDING_TCMALLOC_MAX_TOTAL_THREAD_CACHE_BYTES             = "10737418240"
    BFE_TCMALLOC_BACKGROUND_RELEASE_RATE_BYTES_PER_SECOND     = "4096"
    BFE_TCMALLOC_MAX_TOTAL_THREAD_CACHE_BYTES                 = "10737418240"
    BIDDING_SIGNALS_FETCH_MODE = "REQUIRED"
  }, each.value.runtime_flag_override)

  frontend_domain_name               = local.buyer_domain_name
  frontend_dns_zone                  = local.frontend_dns_zone
  operator                           = local.buyer_operator
  service_account_email              = "<SA_SHORT_NAME>@<YOUR_PROJECT_ID>.iam.gserviceaccount.com"  # CHANGE: service_account_full_name output from project_setup
  vm_startup_delay_seconds           = 200   # Example: 200
  cpu_utilization_percent            = 0.6   # Example: 0.6
  use_confidential_space_debug_image = true   # OPTIONAL: true for CI/staging (allows SSH), false for production
  tee_impersonate_service_accounts   = "a-opallowedusr@ps-pa-coord-prd-g3p-svcacc.iam.gserviceaccount.com,b-opallowedusr@ps-prod-pa-type2-fe82.iam.gserviceaccount.com"
  collector_service_port             = 4317
  collector_startup_script = templatefile("../../../services/autoscaling/collector_startup.tftpl", {
    collector_port           = 4317
    otel_collector_image_uri = "otel/opentelemetry-collector-contrib:0.105.0"
    gcs_hmac_key             = module.secrets.gcs_hmac_key
    gcs_hmac_secret          = module.secrets.gcs_hmac_secret
    gcs_bucket               = "" # Example: ${name of a gcs bucket}
    gcs_bucket_prefix        = "" # Example: "consented-eventmessage-${each.key}"
    file_prefix              = "" # Example: local.buyer_operator
  })
  region_config                     = each.value.region_config
  enable_tee_container_log_redirect = false
}

module "buyer_frontend_load_balancing" {
  source               = "../../../services/frontend_load_balancing"
  environment          = local.environment
  operator             = local.buyer_operator
  frontend_ip_address  = module.buyer[local.environment].frontend_address
  frontend_domain_name = local.buyer_domain_name
  frontend_dns_zone    = local.frontend_dns_zone

  frontend_domain_ssl_certificate_id = local.frontend_domain_ssl_certificate_id
  frontend_certificate_map_id        = local.frontend_certificate_map_id
  frontend_service_name              = "bfe"
  google_compute_backend_service_ids = {
    for buyer_key, buyer in module.buyer :
    buyer_key => buyer.google_compute_backend_service_id
  }
  traffic_weights        = { for key, value in local.buyer_traffic_splits : key => value.traffic_weight if value.traffic_weight > 0 }
  experiment_match_rules = { for key, value in local.buyer_header_experiment : key => value.match_rules if length(value.match_rules) > 0 }
}

module "buyer_dashboard" {
  source = "../../../services/dashboards/buyer_dashboard"
  environment = join("|", concat(
    [for k, v in local.buyer_traffic_splits : k if v.traffic_weight > 0],
  [for k, v in local.buyer_header_experiment : k if length(v.match_rules) > 0]))
}

module "inference_dashboard" {
  source = "../../../services/dashboards/inference_dashboard"
  environment = join("|", concat(
    [for k, v in local.buyer_traffic_splits : k if v.traffic_weight > 0],
  [for k, v in local.buyer_header_experiment : k if length(v.match_rules) > 0]))
}

module "k_anon_dashboard" {
  source = "../../../services/dashboards/k_anon_dashboard"
  environment = join("|", concat(
    [for k, v in local.buyer_traffic_splits : k if v.traffic_weight > 0],
  [for k, v in local.buyer_header_experiment : k if length(v.match_rules) > 0]))
}
