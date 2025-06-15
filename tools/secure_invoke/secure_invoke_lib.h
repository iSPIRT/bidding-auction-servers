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

#ifndef TOOLS_INVOKE_SECURE_INVOKE_LIB_H_
#define TOOLS_INVOKE_SECURE_INVOKE_LIB_H_

#include <memory>
#include <string>

#include <curl/curl.h>

#include "absl/functional/any_invocable.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "api/bidding_auction_servers.grpc.pb.h"
#include "services/common/test/utils/ohttp_utils.h"
#include "services/common/encryption/crypto_client_wrapper_interface.h"

namespace privacy_sandbox::bidding_auction_servers {

inline constexpr absl::Duration timeout = absl::Milliseconds(120000);

struct RequestOptions {
  std::string client_ip;
  std::string user_agent;
  std::string accept_language;
  std::string host_addr;
  bool insecure;
  std::string headers;
  std::string client_key;
  std::string client_cert;
  std::string ca_cert;
  bool enable_verbose;
  std::string batch_file;
  int max_retries;
  int max_concurrent;
  int retry_delay_ms;
  std::string failure_log_path;
  std::string success_log_path;
};

// Sends a request to SFE. The parameters used for the request are retrieved
// from absl flags that are used to run the script.
absl::Status SendRequestToSfe(ClientType client_type, const HpkeKeyset& keyset,
                              std::optional<bool> enable_debug_reporting,
                              std::optional<bool> enable_debug_info,
                              std::optional<bool> enable_unlimited_egress,
                              std::optional<bool> enforce_kanon);

// Sends a request to BFE. The parameters used for the request are retrieved
// from absl flags that are used to run the script.
absl::Status SendRequestToBfe(
    const HpkeKeyset& keyset, std::optional<bool> enable_debug_reporting,
    std::unique_ptr<BuyerFrontEnd::StubInterface> stub = nullptr,
    std::optional<bool> enable_unlimited_egress = std::nullopt);

// Gets contents of the provided file path.
std::string LoadFile(absl::string_view file_path);

//Decrypt Response sent from BFE.
std::string DecryptResponse(
std::unique_ptr<CryptoClientWrapperInterface>& crypto_client,
const std::string& response, 
std::string& secret);

// Returns a JSON string of the OHTTP encrypted of the input GetBidsRawRequest
// to the secure invoke tool.
std::string PackagePlainTextGetBidsRequestToJson(
    const HpkeKeyset& keyset, std::optional<bool> enable_debug_reporting,
    std::optional<bool> enable_unlimited_egress);

// Sends a HTTP request to BFE. The parameters used for the request are
// retrieved from absl flags that are used to run the script.
absl::Status SendHttpRequestToBfe(
    const HpkeKeyset& keyset, std::optional<bool> enable_debug_reporting,
    std::unique_ptr<BuyerFrontEnd::StubInterface> stub = nullptr,
    std::optional<bool> enable_unlimited_egress = std::nullopt);

std::pair<std::string, std::string> GenerateGetBidsRequestJson(
    const HpkeKeyset& keyset,
    const GetBidsRequest::GetBidsRawRequest& get_bids_raw_request);

absl::StatusOr<std::string> ProcessResponse(
    const std::string& response,
    std::unique_ptr<CryptoClientWrapperInterface>& crypto_client,
    const std::string& secret);

RequestOptions CreateRequestOptionsFromFlags();

std::pair<CURLcode, std::string> SendHttpsRequest(
    const std::string& json_request,
    const RequestOptions& request_options);
}  // namespace privacy_sandbox::bidding_auction_servers

#endif  // TOOLS_INVOKE_SECURE_INVOKE_LIB_H_
