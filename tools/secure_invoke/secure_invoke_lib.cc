// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "tools/secure_invoke/secure_invoke_lib.h"

#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <utility>

#include <curl/curl.h>
#include <google/protobuf/text_format.h>
#include <google/protobuf/util/json_util.h>
#include <nlohmann/json.hpp>

#include "absl/container/btree_map.h"
#include "absl/flags/flag.h"
#include "absl/log/log.h"
#include "quiche/oblivious_http/oblivious_http_client.h"
#include "services/common/clients/async_grpc/grpc_client_utils.h"
#include "services/common/clients/buyer_frontend_server/buyer_frontend_async_client.h"
#include "services/common/clients/seller_frontend_server/seller_frontend_async_client.h"
#include "services/common/constants/common_service_flags.h"
#include "services/common/encryption/crypto_client_factory.h"
#include "services/common/encryption/key_fetcher_factory.h"
#include "services/common/util/json_util.h"
#include "src/core/utils/base64.h"
#include "src/encryption/key_fetcher/fake_key_fetcher_manager.h"
#include "tools/secure_invoke/flags.h"
#include "tools/secure_invoke/payload_generator/payload_packaging.h"
#include "tools/secure_invoke/payload_generator/payload_packaging_utils.h"
using json = nlohmann::json;
using google::scp::core::utils::Base64Decode;

namespace privacy_sandbox::bidding_auction_servers {

namespace {

constexpr char kJsonFormat[] = "JSON";

absl::StatusOr<rapidjson::Document> SortAuctionResultBiddingGroups(
    absl::string_view auction_result_json) {
  PS_ASSIGN_OR_RETURN(rapidjson::Document d,
                      ParseJsonString(auction_result_json));

  std::string key_name = "biddingGroups";
  absl::btree_map<std::string, rapidjson::Value> sorted_map;
  if (d.HasMember(key_name.c_str())) {
    for (auto& m : d[key_name.c_str()].GetObject()) {
      sorted_map[m.name.GetString()] = m.value.GetObject();
    }
  }

  d.RemoveMember(key_name.c_str());  // remove old unsorted map

  rapidjson::Value sorted_val(rapidjson::kObjectType);

  for (auto& m : sorted_map) {
    rapidjson::Value key(m.first.c_str(), d.GetAllocator());
    sorted_val.AddMember(key, m.second, d.GetAllocator());
  }

  d.AddMember(rapidjson::Value().SetString(key_name.c_str(), d.GetAllocator()),
              sorted_val, d.GetAllocator());  // add new sorted map

  return d;
}

absl::StatusOr<std::string> ParseSelectAdResponse(
    std::unique_ptr<SelectAdResponse> resp, ClientType client_type,
    quiche::ObliviousHttpRequest::Context& context, const HpkeKeyset& keyset) {
  AuctionResult auction_result;
  std::string nonce;
  // Server component Auction
  if (!resp->key_id().empty()) {
    PS_ASSIGN_OR_RETURN(auction_result,
                        UnpackageResultForServerComponentAuction(
                            *resp->mutable_auction_result_ciphertext(),
                            resp->key_id(), keyset));
  } else {
    PS_ASSIGN_OR_RETURN(auto auction_result_and_nonce,
                        UnpackageAuctionResultAndNonce(
                            *resp->mutable_auction_result_ciphertext(),
                            client_type, context, keyset));
    auction_result = std::move(auction_result_and_nonce.first);
    nonce = std::move(auction_result_and_nonce.second);
  }

  std::string auction_result_json;
  auto auction_result_json_status = google::protobuf::util::MessageToJsonString(
      auction_result, &auction_result_json);
  if (!auction_result_json_status.ok()) {
    return auction_result_json_status;
  }
  // Sort bidding groups for easy comparison.
  PS_ASSIGN_OR_RETURN(rapidjson::Document auction_result_doc,
                      SortAuctionResultBiddingGroups(auction_result_json));

  if (!nonce.empty()) {
    rapidjson::Value nonce_val;
    nonce_val.SetString(nonce.c_str(), auction_result_doc.GetAllocator());
    auction_result_doc.AddMember("nonce", nonce_val,
                                 auction_result_doc.GetAllocator());
  }

  if (!resp->has_debug_info()) {
    return SerializeJsonDoc(auction_result_doc);
  }

  std::string debug_info_json;
  CHECK_OK(google::protobuf::util::MessageToJsonString(resp->debug_info(),
                                                       &debug_info_json));
  absl::StatusOr<rapidjson::Document> debug_info_document =
      ParseJsonString(debug_info_json);
  CHECK_OK(debug_info_document);
  rapidjson::Document output_doc;
  output_doc.SetObject();
  rapidjson::Document::AllocatorType& allocator = output_doc.GetAllocator();
  output_doc.AddMember("auctionResult", std::move(auction_result_doc),
                       allocator);
  output_doc.AddMember("debugInfo", std::move(*debug_info_document), allocator);
  absl::StatusOr<std::string> json_output = SerializeJsonDoc(output_doc);
  CHECK_OK(json_output);
  return *json_output;
}
}  // namespace

absl::Status InvokeSellerFrontEndWithRawRequest(
    absl::string_view raw_select_ad_request_json,
    const RequestOptions& request_options, ClientType client_type,
    const HpkeKeyset& keyset, std::optional<bool> enable_debug_reporting,
    std::optional<bool> enable_debug_info,
    std::optional<bool> enable_unlimited_egress,
    std::optional<bool> enforce_kanon,
    absl::AnyInvocable<void(absl::StatusOr<std::string>) &&> on_done) {
  // Validate input
  if (request_options.host_addr.empty()) {
    return absl::InvalidArgumentError("SFE host address must be specified");
  }

  if (request_options.client_ip.empty()) {
    return absl::InvalidArgumentError("Client IP must be specified");
  }

  if (request_options.user_agent.empty()) {
    return absl::InvalidArgumentError("User Agent must be specified");
  }

  if (request_options.accept_language.empty()) {
    return absl::InvalidArgumentError("Accept Language must be specified");
  }

  // Package request.
  std::pair<std::unique_ptr<SelectAdRequest>,
            quiche::ObliviousHttpRequest::Context>
      request_context_pair = PackagePlainTextSelectAdRequest(
          raw_select_ad_request_json, client_type, keyset,
          enable_debug_reporting, enable_debug_info,
          absl::GetFlag(FLAGS_pas_buyer_input_json), enable_unlimited_egress,
          enforce_kanon);

  // Add request headers.
  RequestMetadata request_metadata;
  request_metadata.emplace("x-bna-client-ip", request_options.client_ip);
  request_metadata.emplace("x-user-agent", request_options.user_agent);
  request_metadata.emplace("x-accept-language",
                           request_options.accept_language);

  // Create client.
  SellerFrontEndServiceClientConfig service_client_config;
  service_client_config.server_addr = request_options.host_addr;
  service_client_config.secure_client = !request_options.insecure;
  SellerFrontEndGrpcClient sfe_client(service_client_config);

  return sfe_client.Execute(
      std::move(request_context_pair.first), request_metadata,
      [context = std::move(request_context_pair.second),
       onDone = std::move(on_done), client_type,
       keyset](absl::StatusOr<std::unique_ptr<SelectAdResponse>> resp) mutable {
        if (resp.ok()) {
          std::move(onDone)(ParseSelectAdResponse(
              std::move(resp.value()), client_type, context, keyset));
        } else {
          std::move(onDone)(resp.status());
        }
      },
      absl::Duration(timeout));
}

absl::Status InvokeBuyerFrontEndWithRawRequest(
    const GetBidsRequest::GetBidsRawRequest& get_bids_raw_request,
    const RequestOptions& request_options, const HpkeKeyset& keyset,
    absl::AnyInvocable<void(absl::StatusOr<std::string>) &&> on_done,
    std::unique_ptr<BuyerFrontEnd::StubInterface> stub = nullptr) {
  // Validate input
  if (request_options.host_addr.empty()) {
    return absl::InvalidArgumentError("BFE host address must be specified");
  }

  if (request_options.client_ip.empty()) {
    return absl::InvalidArgumentError("Client IP must be specified");
  }

  if (request_options.user_agent.empty()) {
    return absl::InvalidArgumentError("User Agent must be specified");
  }

  if (request_options.accept_language.empty()) {
    return absl::InvalidArgumentError("Accept Language must be specified");
  }

  // Add request headers.
  RequestMetadata request_metadata;
  request_metadata.emplace("x-bna-client-ip", request_options.client_ip);
  request_metadata.emplace("x-user-agent", request_options.user_agent);
  request_metadata.emplace("x-accept-language",
                           request_options.accept_language);

  // Create service client.
  BuyerServiceClientConfig service_client_config = {
      .server_addr = request_options.host_addr,
      .secure_client = !request_options.insecure,
  };
  auto key_fetcher_manager =
      std::make_unique<server_common::FakeKeyFetcherManager>(
          keyset.public_key, "unused", std::to_string(keyset.key_id));
  auto crypto_client = CreateCryptoClient();
  BuyerFrontEndAsyncGrpcClient bfe_client(
      key_fetcher_manager.get(), crypto_client.get(), service_client_config,
      std::move(stub));
  absl::Notification notification;

  grpc::ClientContext context;
  for (const auto& it : request_metadata) {
    context.AddMetadata(it.first, it.second);
  }

  auto call_status = bfe_client.ExecuteInternal(
      std::make_unique<GetBidsRequest::GetBidsRawRequest>(get_bids_raw_request),
      &context,
      [onDone = std::move(on_done), &notification, start = absl::Now()](
          absl::StatusOr<std::unique_ptr<GetBidsResponse::GetBidsRawResponse>>
              raw_response,
          ResponseMetadata response_metadata) mutable {
        PS_VLOG(1) << "Received bid response from BFE in "
                   << ((absl::Now() - start) / absl::Milliseconds(1)) << " ms.";
        if (!raw_response.ok()) {
          std::move(onDone)(raw_response.status());
        } else {
          std::string response;
          auto response_status = google::protobuf::util::MessageToJsonString(
              **raw_response, &response);
          if (!response_status.ok()) {
            std::move(onDone)(absl::InternalError(
                "Failed to convert the server response to JSON string"));
          } else {
            std::move(onDone)(std::move(response));
          }
        }
        notification.Notify();
      },
      absl::Duration(timeout));
  CHECK(call_status.ok()) << call_status;
  notification.WaitForNotification();
  return call_status;
}

std::string LoadFile(absl::string_view file_path) {
  std::ifstream ifs(file_path.data());
  return std::string((std::istreambuf_iterator<char>(ifs)),
                     (std::istreambuf_iterator<char>()));
}

absl::Status SendRequestToSfe(ClientType client_type, const HpkeKeyset& keyset,
                              std::optional<bool> enable_debug_reporting,
                              std::optional<bool> enable_debug_info,
                              std::optional<bool> enable_unlimited_egress,
                              std::optional<bool> enforce_kanon) {
  std::string raw_select_ad_request_json = absl::GetFlag(FLAGS_json_input_str);
  if (raw_select_ad_request_json.empty()) {
    raw_select_ad_request_json = LoadFile(absl::GetFlag(FLAGS_input_file));
  }
  privacy_sandbox::bidding_auction_servers::RequestOptions options;
  options.host_addr = absl::GetFlag(FLAGS_host_addr);
  options.client_ip = absl::GetFlag(FLAGS_client_ip);
  options.user_agent = absl::GetFlag(FLAGS_client_user_agent);
  options.accept_language = absl::GetFlag(FLAGS_client_accept_language);
  options.insecure = absl::GetFlag(FLAGS_insecure);
  absl::Notification notification;
  absl::Status status = privacy_sandbox::bidding_auction_servers::
      InvokeSellerFrontEndWithRawRequest(
          raw_select_ad_request_json, options, client_type, keyset,
          enable_debug_reporting, enable_debug_info, enable_unlimited_egress,
          enforce_kanon, [&notification](absl::StatusOr<std::string> output) {
            if (output.ok()) {
              // Standard output to compare response
              // programatically by utilities.
              std::cout << *output;
            } else {
              std::cerr << output.status();
            }
            notification.Notify();
          });
  CHECK(status.ok()) << status;
  notification.WaitForNotification();
  return status;
}

GetBidsRequest::GetBidsRawRequest GetBidsRawRequestFromInput(
    std::optional<bool> enable_debug_reporting,
    std::optional<bool> enable_unlimited_egress) {
  std::string raw_get_bids_request_str = absl::GetFlag(FLAGS_json_input_str);
  const bool is_json = (!raw_get_bids_request_str.empty() ||
                        absl::GetFlag(FLAGS_input_format) == kJsonFormat);
  GetBidsRequest::GetBidsRawRequest get_bids_raw_request;
  if (enable_debug_reporting) {
    get_bids_raw_request.set_enable_debug_reporting(*enable_debug_reporting);
  }
  if (enable_unlimited_egress) {
    get_bids_raw_request.set_enable_unlimited_egress(*enable_unlimited_egress);
  }
  if (is_json) {
    if (raw_get_bids_request_str.empty()) {
      raw_get_bids_request_str = LoadFile(absl::GetFlag(FLAGS_input_file));
    }
    auto result = google::protobuf::util::JsonStringToMessage(
        raw_get_bids_request_str, &get_bids_raw_request);
    CHECK(result.ok())
        << "Failed to convert the provided raw request JSON to proto "
        << "(Is the input malformed?). Input:\n"
        << raw_get_bids_request_str << "\nError:\n:" << result;
  } else {
    raw_get_bids_request_str = LoadFile(absl::GetFlag(FLAGS_input_file));
    CHECK(google::protobuf::TextFormat::ParseFromString(
        raw_get_bids_request_str, &get_bids_raw_request))
        << "Failed to create proto object from the input file. Input:\n"
        << raw_get_bids_request_str;
  }
  return get_bids_raw_request;
}

std::string PackagePlainTextGetBidsRequestToJson(
    const HpkeKeyset& keyset, std::optional<bool> enable_debug_reporting,
    std::optional<bool> enable_unlimited_egress) {
  GetBidsRequest::GetBidsRawRequest get_bids_raw_request =
      GetBidsRawRequestFromInput(enable_debug_reporting,
                                 enable_unlimited_egress);
  auto key_fetcher_manager =
      std::make_unique<server_common::FakeKeyFetcherManager>(
          keyset.public_key, "unused", std::to_string(keyset.key_id));
  auto crypto_client = CreateCryptoClient();
  auto secret_request = EncryptRequestWithHpke<GetBidsRequest>(
      get_bids_raw_request.SerializeAsString(), *crypto_client,
      *key_fetcher_manager, server_common::CloudPlatform::kGcp);
  CHECK(secret_request.ok()) << secret_request.status();
  std::string get_bids_request_json;
  auto get_bids_request_json_status =
      google::protobuf::util::MessageToJsonString(*secret_request->second,
                                                  &get_bids_request_json);
  CHECK(get_bids_request_json_status.ok()) << get_bids_request_json_status;
  return get_bids_request_json;
}

absl::Status SendRequestToBfe(
    const HpkeKeyset& keyset, std::optional<bool> enable_debug_reporting,
    std::unique_ptr<BuyerFrontEnd::StubInterface> stub,
    std::optional<bool> enable_unlimited_egress) {
  GetBidsRequest::GetBidsRawRequest get_bids_raw_request =
      GetBidsRawRequestFromInput(enable_debug_reporting,
                                 enable_unlimited_egress);
  privacy_sandbox::bidding_auction_servers::RequestOptions request_options;
  request_options.host_addr = absl::GetFlag(FLAGS_host_addr);
  request_options.client_ip = absl::GetFlag(FLAGS_client_ip);
  request_options.user_agent = absl::GetFlag(FLAGS_client_user_agent);
  request_options.accept_language = absl::GetFlag(FLAGS_client_accept_language);
  request_options.insecure = absl::GetFlag(FLAGS_insecure);
  absl::Status status = absl::OkStatus();
  auto call_status = privacy_sandbox::bidding_auction_servers::
      InvokeBuyerFrontEndWithRawRequest(
          get_bids_raw_request, request_options, keyset,
          [&status](absl::StatusOr<std::string> output) {
            if (output.ok()) {
              // Standard output to compare response
              // programatically by utilities.
              std::cout << *output;
            } else {
              status = output.status();
              std::cerr << output.status();
            }
          },
          std::move(stub));
  CHECK(call_status.ok()) << call_status;
  return status;
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
  size_t total_size = size * nmemb;
  std::string* response = static_cast<std::string*>(userp);
  response->append(static_cast<char*>(contents), total_size);
  return total_size;
}

std::map<std::string, std::string> ParseHeaders(const std::string& input) {
  std::map<std::string, std::string> result;
  std::stringstream ss(input);
  std::string pair;

  while (std::getline(ss, pair, ';')) {
    size_t pos = pair.find('=');
    if (pos != std::string::npos) {
      std::string key = pair.substr(0, pos);
      std::string value = pair.substr(pos + 1);
      result[key] = value;
    }
  }
  return result;
}
// Debug call back to print TLS exchange
static int curl_debug_callback(CURL *handle, curl_infotype type, char *data, size_t size, void *userptr) {
  const char *type_name = "Unknown";
  
  switch (type) {
    case CURLINFO_TEXT:
      type_name = "Info";
      break;
    case CURLINFO_HEADER_IN:
      type_name = "<= Recv header";
      break;
    case CURLINFO_HEADER_OUT:
      type_name = "=> Send header";
      break;
    case CURLINFO_DATA_IN:
      type_name = "<= Recv data";
      break;
    case CURLINFO_DATA_OUT:
      type_name = "=> Send data";
      break;
    case CURLINFO_SSL_DATA_IN:
      type_name = "<= Recv SSL data";
      fprintf(stderr, "SSL IN [%zu bytes]:\n", size);
      break;
    case CURLINFO_SSL_DATA_OUT:
      type_name = "=> Send SSL data";
      fprintf(stderr, "SSL OUT [%zu bytes]:\n", size);
      break;
    default:
      break;
  }
  // Print SSL/TLS data with special handling
  if (type == CURLINFO_SSL_DATA_IN || type == CURLINFO_SSL_DATA_OUT) {
    // Just print the size for binary data
    fprintf(stderr, "[%s] [%zu bytes of SSL data]\n", type_name, size);
  } else {
    // For text data, print the actual content
    fprintf(stderr, "[%s] %.*s\n", type_name, (int)size, data);
  }
  return 0;
}
// New helper function to initialize CURL with common settings
std::pair<CURL*, struct curl_slist*> CurlInitialize(
    const RequestOptions& request_options,
    const std::string& request_json) {
  
  CURL* curl = curl_easy_init();  // Initialize cURL
  if (!curl) {
    LOG(FATAL) << "Failed to initialize cURL.";
    return {nullptr, nullptr};
  }
  struct curl_slist* headers = nullptr;
  // Add standard headers to headers list
  headers = curl_slist_append(headers, "Content-Type: application/json");
  headers = curl_slist_append(
      headers, ("x-bna-client-ip: " + request_options.client_ip).c_str());
  headers = curl_slist_append(
      headers, ("x-user-agent: " + request_options.user_agent).c_str());
  headers = curl_slist_append(
      headers,
      ("x-accept-language: " + request_options.accept_language).c_str());
  // Add custom headers if provided to headers list
  if (!request_options.headers.empty()) {
    auto parsed_headers = ParseHeaders(request_options.headers);
    for (const auto& [key, value] : parsed_headers) {
      headers = curl_slist_append(headers, (key + ": " + value).c_str());
    }
  }
  // Set headers and URL
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_URL, request_options.host_addr.c_str());
  // Set request parameters
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  // Set request timeout in seconds
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

  
  // Set mTLS certificate and key if provided
  if (request_options.client_key.empty() !=
      request_options.client_cert.empty()) {
    LOG(ERROR) << "Both client_cert and client_key must be provided or neither.";
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return {nullptr, nullptr};
  }
  // Set client key and cert if provided
  if (!request_options.client_key.empty() && 
      !request_options.client_cert.empty()) {
    curl_easy_setopt(curl, CURLOPT_SSLKEY,
                     request_options.client_key.c_str());
    curl_easy_setopt(curl, CURLOPT_SSLCERT,
                     request_options.client_cert.c_str());            
    LOG(INFO) << "Client key and cert settings applied to CURL";
  } else {
    LOG(INFO) << "Not using client key or cert";
  }
  // Set CA certificate if provided
  if (!request_options.ca_cert.empty()) {
    curl_easy_setopt(curl, CURLOPT_CAINFO,
                     request_options.ca_cert.c_str());
    LOG(INFO) << "Using CA cert: " << request_options.ca_cert;
  }
  // Configure SSL security
  if (request_options.insecure) {
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    LOG(WARNING) << "SSL verification disabled, security may be compromised";
  }
  // Enable debugging if requested
  if (absl::GetFlag(FLAGS_enable_verbose)) {
    LOG(INFO) << "Enabling cURL debug callback";
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, curl_debug_callback);
    curl_easy_setopt(curl, CURLOPT_DEBUGDATA, NULL);
    curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L); // Enable detailed SSL trace
  }
  return {curl, headers};
}

// New helper function to create RequestOptions from flags
RequestOptions CreateRequestOptionsFromFlags() {
  privacy_sandbox::bidding_auction_servers::RequestOptions request_options;
  request_options.host_addr = absl::GetFlag(FLAGS_host_addr);
  request_options.client_ip = absl::GetFlag(FLAGS_client_ip);
  request_options.user_agent = absl::GetFlag(FLAGS_client_user_agent);
  request_options.accept_language = absl::GetFlag(FLAGS_client_accept_language);
  request_options.insecure = absl::GetFlag(FLAGS_insecure);
  request_options.headers = absl::GetFlag(FLAGS_headers);
  request_options.client_key = absl::GetFlag(FLAGS_client_key);
  request_options.client_cert = absl::GetFlag(FLAGS_client_cert);
  request_options.ca_cert = absl::GetFlag(FLAGS_ca_cert);
  // Validate request options (moved from CurlInitialize)
  CHECK(!request_options.host_addr.empty()) << "Host address must be specified";
  CHECK(!request_options.client_ip.empty()) << "Client IP must be specified";
  CHECK(!request_options.user_agent.empty()) << "User Agent must be specified";
  CHECK(!request_options.accept_language.empty()) << "Accept Language must be specified";
  // mTLS validation
  CHECK(request_options.client_key.empty() == request_options.client_cert.empty())
      << "Both client_cert and client_key must be provided or neither.";
  // Debug output to check flag values
  if(absl::GetFlag(FLAGS_enable_verbose)) {
    LOG(INFO) << "Created RequestOptions with the following values:";
    LOG(INFO) << "Host: " << request_options.host_addr;
    LOG(INFO) << "client key: '" << request_options.client_key << "'";
    LOG(INFO) << "client cert: '" << request_options.client_cert << "'";
    LOG(INFO) << "CA cert: '" << request_options.ca_cert << "'";
    LOG(INFO) << "Insecure mode: " << (request_options.insecure ? "true" : "false");
    LOG(INFO) << "Client IP: " << request_options.client_ip;
    LOG(INFO) << "User Agent: " << request_options.user_agent;
    LOG(INFO) << "Accept Language: " << request_options.accept_language;
    LOG(INFO) << "Headers: " << request_options.headers;
  }
  return request_options;
}
// Function to send HTTPS request
std::pair<CURLcode, std::string> SendHttpsRequest(
    const std::string& request_json,
    const RequestOptions& request_options) {
  // Initialize curl with common settings
  auto [curl, headers] = CurlInitialize(request_options, request_json);
  if (!curl) {
    return {CURLE_FAILED_INIT, "Failed to initialize cURL"};
  }
  // Prepare for response
  std::string response;
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_json.c_str());
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
  // Perform the request
  CURLcode res = curl_easy_perform(curl);
  // Cleanup
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  // Return the result of the cURL request
  return {res, response};
}

// New helper function to generate the JSON request for BFE
std::pair<std::string, std::string> GenerateGetBidsRequestJson(
    const HpkeKeyset& keyset,
    const GetBidsRequest::GetBidsRawRequest& get_bids_raw_request) {
  auto key_fetcher_manager =
      std::make_unique<server_common::FakeKeyFetcherManager>(
          keyset.public_key, "unused", std::to_string(keyset.key_id));
  auto crypto_client = CreateCryptoClient();
  auto secret_request = EncryptRequestWithHpke<GetBidsRequest>(
      get_bids_raw_request.SerializeAsString(), *crypto_client,
      *key_fetcher_manager, server_common::CloudPlatform::kGcp);
  CHECK(secret_request.ok()) << secret_request.status();
  std::string get_bids_request_json;
  auto get_bids_request_json_status =
      google::protobuf::util::MessageToJsonString(*secret_request->second,
                                                 &get_bids_request_json);
  CHECK(get_bids_request_json_status.ok()) << get_bids_request_json_status;
  // Return both the secret and the JSON request
  return {get_bids_request_json, secret_request->first};
}

std::string DecryptResponse(
    std::unique_ptr<CryptoClientWrapperInterface>& crypto_client,
    const std::string& response, const std::string& secret) {
  absl::StatusOr<google::cmrt::sdk::crypto_service::v1::AeadDecryptResponse>
      decrypt_response = crypto_client->AeadDecrypt(response, secret);
  CHECK(decrypt_response.ok()) << decrypt_response.status();
  std::string decrypted_payload =
      std::move(*decrypt_response->mutable_payload());
  return decrypted_payload;
}

// New helper function to process the HTTP response with better error handling
absl::StatusOr<std::string> ProcessResponse(
    const std::string& response,
    std::unique_ptr<CryptoClientWrapperInterface>& crypto_client,
    const std::string& secret) {
  // Parse response JSON
  json response_json;
  try {
    response_json = json::parse(response);
  } catch (const json::parse_error& e) {
    LOG(ERROR) << "Failed to parse response JSON: " << e.what();
    return absl::InvalidArgumentError(
        absl::StrCat("Failed to parse response JSON: ", e.what()));
  }
  // Extract response ciphertext
  std::string response_ciphertext;
  try {
    response_ciphertext = response_json.at("responseCiphertext").get<std::string>();
  } catch (const json::exception& e) {
    LOG(ERROR) << "Failed to extract responseCiphertext from response: " << e.what();
    return absl::InvalidArgumentError("Response missing 'responseCiphertext' field");
  }
  // Decode the base64 ciphertext
  std::string decoded_ciphertext;
  if (!Base64Decode(response_ciphertext, decoded_ciphertext)) {
    LOG(ERROR) << "Failed to decode base64 response ciphertext";
    return absl::InvalidArgumentError("Failed to decode base64 response ciphertext");
  }
  if (absl::GetFlag(FLAGS_enable_verbose)) {
    LOG(INFO) << "Response ciphertext length: " << response_ciphertext.size();
  }
  // Decrypt the response
  PS_VLOG(6) << "Decrypting the response...";
  std::string decrypt_response;
  try {
    decrypt_response = DecryptResponse(crypto_client, decoded_ciphertext, secret);
  } catch (const std::exception& e) {
    LOG(ERROR) << "Decryption failed: " << e.what();
    return absl::InternalError(absl::StrCat("Decryption failed: ", e.what()));
  }
  // Parse the decrypted response into the proto
  auto raw_response = std::make_unique<GetBidsResponse::GetBidsRawResponse>();
  if (!raw_response->ParseFromString(decrypt_response)) {
    LOG(ERROR) << "Failed to parse proto from decrypted response";
    return absl::InvalidArgumentError(
        "Failed to parse GetBidsRawResponse proto from decrypted response");
  }
  LOG(INFO) << "Decryption/decoding of response succeeded";
  if (absl::GetFlag(FLAGS_enable_verbose)) {
    LOG(INFO) << "Response details: " << raw_response->DebugString();
  }
  // Convert proto to JSON string since we need to return a string
  std::string json_output;
  auto json_status = google::protobuf::util::MessageToJsonString(
      *raw_response, &json_output);
  if (!json_status.ok()) {
    LOG(ERROR) << "Failed to convert proto to JSON: " << json_status.message();
    return absl::InternalError("Failed to convert proto to JSON");
  }
  LOG(INFO) << "Decryption/decoding of response succeeded";
  if (absl::GetFlag(FLAGS_enable_verbose)) {
    LOG(INFO) << "Response details: " << raw_response->DebugString();
  }
  // Return the JSON string instead of the proto object
  return json_output;
}

absl::Status SendHttpRequestToBfe(
    const HpkeKeyset& keyset, std::optional<bool> enable_debug_reporting,
    std::unique_ptr<BuyerFrontEnd::StubInterface> stub,
    std::optional<bool> enable_unlimited_egress) {  
  GetBidsRequest::GetBidsRawRequest get_bids_raw_request =
      GetBidsRawRequestFromInput(enable_debug_reporting,
                                 enable_unlimited_egress);
  // Generate the JSON request and get the secret
  auto [get_bids_request_json, secret]= GenerateGetBidsRequestJson(
      keyset, get_bids_raw_request);
  std::cout << "insider rest_invoke " << get_bids_request_json << std::endl;
  // Get request options from flags - moved from SendHttpsRequest
  RequestOptions request_options = CreateRequestOptionsFromFlags();
  // Send the HTTPS request
  auto [result, response] = SendHttpsRequest(get_bids_request_json,request_options);
  std::cout << "Response from HTTPS request: " << response
            << std::endl;  // Print the response message
  if (result != CURLE_OK) {
    LOG(ERROR) << "HTTPS request failed: " << curl_easy_strerror(result);
    return absl::UnavailableError(curl_easy_strerror(result));
  } 
  LOG(INFO) << "HTTPS request completed successfully.";
  // Process the response using the new function
  auto crypto_client = CreateCryptoClient();
  auto raw_response_or = ProcessResponse(response, crypto_client, secret);
  if (!raw_response_or.ok()) {
    LOG(ERROR) << "Failed to process response: " << raw_response_or.status();
    return raw_response_or.status();
  }
  auto& raw_response = raw_response_or.value();
  LOG(INFO) << "Successfully processed response with " << raw_response
            << std::endl;
  return absl::OkStatus();

}

}  // namespace privacy_sandbox::bidding_auction_servers
