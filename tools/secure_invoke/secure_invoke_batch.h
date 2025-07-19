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

#ifndef TOOLS_SECURE_INVOKE_SECURE_INVOKE_BATCH_H_
#define TOOLS_SECURE_INVOKE_SECURE_INVOKE_BATCH_H_

#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/synchronization/mutex.h"
#include "tools/secure_invoke/secure_invoke_lib.h"

namespace privacy_sandbox::bidding_auction_servers {

// Data structure for batch request entries
struct RequestEntry {
  int id;
  std::string json_request;
  int attempts = 0;
  absl::Status status = absl::OkStatus();
  std::string raw_json_response;
};

// Data structure for successful request logging
struct SuccessLogEntry {
  int id;
  int attempts;
  std::string raw_json_response;
};

struct DelayedRequest {
  RequestEntry* request;
  std::chrono::steady_clock::time_point retry_time;
};

class BatchRequestProcessor {
 public:
  BatchRequestProcessor(const std::string& batch_file, 
                       int max_retries,
                       int max_concurrent_requests, 
                       int retry_delay_ms,
                       const std::string& failure_log_path,
                       const std::string& success_log_path,
                       const HpkeKeyset& keyset,
                       std::optional<bool> enable_debug_reporting,
                       std::optional<bool> enable_unlimited_egress);

  // Run the batch processor
  absl::Status Run();

 private:
  // Read requests from the batch file
  absl::Status ReadRequestsFromFile();

  // Process a single request
  void ProcessRequest(RequestEntry* request);
  
  // Handle the result of a request (retry or completion)
  void HandleRequestResult(RequestEntry* request);
  
  // Write failure logs to file
  absl::Status WriteFailureLog();
  
  // Write success logs to file  
  absl::Status WriteSuccessLog();

  // Member variables
  std::string batch_file_;
  int max_retries_;
  int max_concurrent_requests_;
  int retry_delay_ms_;
  std::string failure_log_path_;
  std::string success_log_path_;
  HpkeKeyset keyset_;
  bool enable_debug_reporting_;
  bool enable_unlimited_egress_;
  
  // Request options initialized once and reused
  RequestOptions request_options_;
  
  // Request and response tracking
  std::vector<RequestEntry> requests_;
  std::deque<RequestEntry*> pending_queue_;
  std::vector<RequestEntry> failures_;
  std::vector<SuccessLogEntry> success_logs_;
  std::atomic<int> remaining_requests_;
  std::mutex request_queue_mutex_;
  std::mutex result_log_mutex_;
  std::vector<DelayedRequest> delayed_requests_;
};


} // namespace privacy_sandbox::bidding_auction_servers

#endif  // TOOLS_SECURE_INVOKE_SECURE_INVOKE_BATCH_H_