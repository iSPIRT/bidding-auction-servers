#include <deque>  
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <future>
#include <chrono>
#include <atomic>
#include <mutex>
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include <curl/curl.h>
#include "tools/secure_invoke/secure_invoke_lib.h"
#include "tools/secure_invoke/flags.h"
#include <nlohmann/json.hpp>
#include "services/common/encryption/crypto_client_factory.h"
#include "tools/secure_invoke/secure_invoke_batch.h"

using json = nlohmann::json;

namespace privacy_sandbox::bidding_auction_servers {

BatchRequestProcessor::BatchRequestProcessor(const std::string& batch_file, int max_retries,
                      int max_concurrent_requests, int retry_delay_ms,
                      const std::string& failure_log_path,
                      const std::string& success_log_path,
                      const HpkeKeyset& keyset,
                      std::optional<bool> enable_debug_reporting,
                      std::optional<bool> enable_unlimited_egress)
    : batch_file_(batch_file), 
      max_retries_(max_retries),
      max_concurrent_requests_(max_concurrent_requests),
      retry_delay_ms_(retry_delay_ms),
      failure_log_path_(failure_log_path),
      success_log_path_(success_log_path),
      keyset_(keyset),
      enable_debug_reporting_(enable_debug_reporting),
      enable_unlimited_egress_(enable_unlimited_egress),
      remaining_requests_(0) {
        // Initialize request_options_ in the constructor
        request_options_ = CreateRequestOptionsFromFlags();
        //retry_thread_ = std::thread([this]() { RetryThreadFunc(); });
        std::cout << "Initialized request_options_ during BatchRequestProcessor construction" << std::endl;
}

// Implementation of BatchRequestProcessor::Run()
absl::Status BatchRequestProcessor::Run() {
  // Record start time
  auto start_time = std::chrono::steady_clock::now();
  LOG(INFO) << "Batch processing started at " 
            << std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())
            << " (" << absl::FormatTime("%Y-%m-%d %H:%M:%S", absl::Now(), absl::LocalTimeZone()) << ")";

  // Read all requests from the file
  auto read_status = ReadRequestsFromFile();
  if (!read_status.ok()) {
    return read_status;
  }
  LOG(INFO) << "Loaded " << requests_.size() << " requests from file";
  // Initialize the request options once
  request_options_ = CreateRequestOptionsFromFlags();
  LOG(INFO) << "Initialized request options";
  // Process all requests with concurrency control
  remaining_requests_ = requests_.size();
  // Use a pool of worker threads to process requests
  std::vector<std::thread> workers;
  // Queue initial batch of requests
  {
    std::lock_guard<std::mutex> lock(request_queue_mutex_);
    for (auto& req : requests_) {
      pending_queue_.push_back(&req);
    }
  }
  // Start worker threads
  for (int i = 0; i < max_concurrent_requests_; i++) {
    workers.emplace_back([this]() {
      while (true) {
          // Get next request from queue
          RequestEntry* request = nullptr;
          bool go_to_sleep = false;
          auto now = std::chrono::steady_clock::now();
          {
            std::lock_guard<std::mutex> lock(request_queue_mutex_);
            // Check if any delayed requests are ready
            auto it = delayed_requests_.begin();
            while (it != delayed_requests_.end()) {
              if (now >= it->retry_time) {
                // This request is ready to retry
                pending_queue_.push_back(it->request);
                LOG(INFO) << "Moving request " << it->request->id << " from delayed to pending queue";
                it = delayed_requests_.erase(it);
              } else {
                ++it;
              }
            }
            if (pending_queue_.empty()) {
              if (remaining_requests_ <= 0) {
                // No more work to do
                break;
              }
              go_to_sleep = true;
            } else {
              // Pop the next request
              request = pending_queue_.front();
              pending_queue_.pop_front();
            }
          }
          // Sleep outside the lock if needed
          if (go_to_sleep) {
            //std::cout << "Worker: Queue empty, Remaining: " << remaining_requests_ << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
          }
        // Process the request
        ProcessRequest(request);
      }
    });
  }
  // Wait for all threads to complete
  for (auto& thread : workers) {
    if (thread.joinable()) {
      thread.join();
    }
  }
  // Log results
  int success_count = 0;
  for (const auto& req : requests_) {
    if (req.status.ok()) {
      success_count++;
    }
  }
  LOG(INFO) << "Processed " << requests_.size() << " requests: " 
            << success_count << " succeeded, " 
            << (requests_.size() - success_count) << " failed";
  // Write failure logs
  if (!failures_.empty()) {
    auto failure_status = WriteFailureLog();
    if (!failure_status.ok()) {
      LOG(WARNING) << "Failed to write failure log: " << failure_status;
    }
  }
  // Write success logs
  if (!success_logs_.empty()) {
    auto success_status = WriteSuccessLog();
    if (!success_status.ok()) {
      LOG(WARNING) << "Failed to write success log: " << success_status;
    }
  }
  // Record end time and calculate duration
  auto end_time = std::chrono::steady_clock::now();
  auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
  
  // Calculate average time per request
  double avg_time_ms = static_cast<double>(duration_ms) / requests_.size();
  
  LOG(INFO) << "Batch processing completed at " 
            << std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())
            << " (" << absl::FormatTime("%Y-%m-%d %H:%M:%S", absl::Now(), absl::LocalTimeZone()) << ")";
  LOG(INFO) << "Total processing time: " << duration_ms << "ms (" 
            << (duration_ms / 1000.0) << " seconds)";
  LOG(INFO) << "Average time per request: " << avg_time_ms << "ms";
  
  return absl::OkStatus();
}

// Implementation of BatchRequestProcessor::ReadRequestsFromFile()
absl::Status BatchRequestProcessor::ReadRequestsFromFile() {
  std::ifstream file(batch_file_);
  if (!file.is_open()) {
    return absl::NotFoundError("Could not open request file: " + batch_file_);
  }
  std::string line;
  int request_id;
  while (std::getline(file, line)) {
    // Skip empty lines
    if (line.empty()) {
      continue;
    }
    try {
    // Parse the line as a JSON object
    nlohmann::json obj = nlohmann::json::parse(line);

    // Check if the JSON has a request field
    if (!obj.contains("request") || !obj.contains("id")) {
      return absl::InvalidArgumentError("JSON object does not contain 'request' or 'id' field: " + line);
    }
    request_id = obj["id"].get<int>();
    // Create request entry and add to our collection
    RequestEntry entry;
    entry.id = request_id;
    entry.json_request = obj["request"].dump();  // Convert request to JSON string
    requests_.push_back(entry);
    
    //LOG(INFO) << "Added request id=" << request_id;
    } catch (const std::exception& e) {
          std::cerr << "JSON parse error: " << e.what() << " on line: " << line << '\n';
          // Continue processing other lines instead of exiting
    }
  }
  return absl::OkStatus();
}
  
void BatchRequestProcessor::ProcessRequest(RequestEntry* request) {
  // Increment attempt counter
  request->attempts++;
  // Generate Protobuf request from json
  GetBidsRequest::GetBidsRawRequest get_bids_raw_request;
  auto result_pb = google::protobuf::util::JsonStringToMessage(
        request->json_request, &get_bids_raw_request);
  if (!result_pb.ok()) {
    std::string error_msg = absl::StrCat("Failed to parse JSON for request id ",
                                          request->id, ": ", result_pb.message());
    LOG(ERROR) << error_msg;
    request->status = absl::InvalidArgumentError(error_msg);
    HandleRequestResult(request);
    return;
  }
  // Generate the JSON request and get the secret
  auto [get_bids_request_json, secret]= GenerateGetBidsRequestJson(
      keyset_, get_bids_raw_request);
  std::cout << "insider rest_invoke " << get_bids_request_json << std::endl;
   // Send the HTTPS request
  auto [result, response] = SendHttpsRequest(get_bids_request_json, request_options_);
  // Check if the HTTP request was successful
  if (result != CURLE_OK) {
    std::string error_msg = curl_easy_strerror(result);
    std::cerr << "HTTP request failed for id " << request->id
              << ": " << error_msg << std::endl;
    // Set error status
    request->status = absl::UnavailableError(error_msg);
    // Handle retry logic
    HandleRequestResult(request);
    return;
  }
  try {
    // Process the response
    auto crypto_client = CreateCryptoClient();
    auto raw_response_or = ProcessResponse(response, crypto_client, secret);
    if (!raw_response_or.ok()) {
      // Response processing failed
      request->status = raw_response_or.status();
      LOG(ERROR) << "Failed to process response: " << raw_response_or.status();
    } else {
      // Successfully processed response
      request->status = absl::OkStatus();
      // IMPORTANT: Store response exactly once, not twice
      request->raw_json_response = raw_response_or.value();
      std::cout << "Request " << request->id << " succeeded!" << std::endl;
    }
  } catch (const std::exception& e) {
    // Handle any exceptions during processing
    request->status = absl::InternalError(
      std::string("Exception during response processing: ") + e.what());
    LOG(ERROR) << "Exception for id " << request->id << ": " << e.what();
  }
  HandleRequestResult(request);
}

// HandleRequestResult method
void BatchRequestProcessor::HandleRequestResult(RequestEntry* request) {
  // Check if we need to retry
  if (!request->status.ok() && 
      request->attempts < max_retries_ &&
      request->status.code() == absl::StatusCode::kUnavailable) {
    LOG(ERROR) << "HTTP request failed for id " << request->id
                << " (attempt " << request->attempts << "/" << max_retries_ 
                << "): " << request->status.message();
    auto retry_time = std::chrono::steady_clock::now() + 
                     std::chrono::milliseconds(retry_delay_ms_);
    // Add to delayed requests list
    {
      std::lock_guard<std::mutex> lock(request_queue_mutex_);
      delayed_requests_.push_back({request, retry_time});
      LOG(INFO) << "Scheduled request " << request->id << " for retry in " 
                << retry_delay_ms_ << "ms";
    }
    // Queue for retry after delay
    /*std::thread([this, request]() {
      std::this_thread::sleep_for(std::chrono::milliseconds(retry_delay_ms_));
      {
      std::lock_guard<std::mutex> lock(request_queue_mutex_);
      pending_queue_.push_back(request);
      }
    }).detach();*/
  } else {
    /* Either succeeded or max retries reached
     push to success or failure log under mutex lock*/
    std::lock_guard<std::mutex> lock(result_log_mutex_);
    
    if (!request->status.ok()) {
      // Log as final failure
      failures_.push_back(*request);
      if (request->status.code() == absl::StatusCode::kUnavailable && 
          request->attempts >= max_retries_) {
        LOG(ERROR) << "HTTP request for id " << request->id
                    << " failed permanently after " << request->attempts 
                    << " attempts: " << request->status.message();
      } else {
        // Response processing error or other non-retryable error
        LOG(ERROR) << "Request " << request->id
                    << " failed with non-retryable error: " 
                    << request->status.message();
      }
    } else {
      // Create a success log entry with the response
      SuccessLogEntry success_entry;
      success_entry.id = request->id;
      success_entry.attempts = request->attempts;
      success_entry.raw_json_response = request->raw_json_response; // Store raw JSON
      // Store the success entry
      success_logs_.push_back(std::move(success_entry));
      LOG(INFO) << "Request " << request->id << " completed successfully";      
    }
    // Mark this request as complete
    remaining_requests_--;
  }
}
  
// Update WriteSuccessLog method to include raw JSON
absl::Status BatchRequestProcessor::WriteSuccessLog() {
  if (success_logs_.empty()) {
      return absl::OkStatus();
  }
  // Extract the directory path from success_log_path_
  std::string directory_path = success_log_path_.substr(0, success_log_path_.find_last_of("/\\"));
  // Create the directory if it doesn't exist
  if (!directory_path.empty()) {
    std::string mkdir_command = "mkdir -p " + directory_path;
    int result = system(mkdir_command.c_str());
    if (result != 0) {
      return absl::InternalError("Failed to create directory for success log: " + directory_path);
    }
  }
  std::ofstream file(success_log_path_);
  if (!file.is_open()) {
      return absl::InternalError("Failed to open success log file: " + success_log_path_);
  }
  // Process each success entry
  for (const auto& entry : success_logs_) {
      try {
      // Create a new JSON object with id and response keys
      json output_obj;
      output_obj["id"] = entry.id;
      
      // Parse the raw_json_response if it's valid JSON
      json parsed_response = json::parse(entry.raw_json_response);
      output_obj["response"] = parsed_response;
      
      // Write as a single line in JSONL format
      file << output_obj.dump() << "\n";
      
      } catch (const std::exception& e) {
      // If parsing fails, create a simpler object with the raw string
      json output_obj;
      output_obj["id"] = entry.id;
      output_obj["response"] = entry.raw_json_response;
      file << output_obj.dump() << "\n";
      }
  }
  file.close();
  std::cout << "Wrote " << success_logs_.size() << " successful responses to " 
              << success_log_path_ << " in JSONL format" << std::endl;
              
  return absl::OkStatus();
}

// Implementation of BatchRequestProcessor::WriteFailureLog()
absl::Status BatchRequestProcessor::WriteFailureLog() {
  if (failures_.empty()) {
      return absl::OkStatus();
  }
  std::ofstream file(failure_log_path_, std::ios::out | std::ios::trunc);
  if (!file.is_open()) {
    return absl::InternalError("Failed to open failure log file: " + failure_log_path_);
  }    
  // Process each failure entry
  for (const auto& failure : failures_) {
    try {
      // Create a new JSON object with id, error details
      json output_obj;
      output_obj["id"] = failure.id;
      
      // Create an error object
      json error_obj;
      //error_obj["code"] = static_cast<int>(failure.status.code());
      error_obj["message"] = failure.status.message();
      error_obj["attempts"] = failure.attempts;
      
      // Add the error object to the output
      output_obj["error"] = error_obj;
      
      // Add original request if available
      try {
        json request_json = json::parse(failure.json_request);
        output_obj["request"] = request_json;
      } catch (...) {
        // If parsing fails, include as string
        output_obj["request"] = failure.json_request;
      }
      
      // Write as a single line in JSONL format
      file << output_obj.dump() << "\n";
      
    } catch (const std::exception& e) {
      // Fallback to simple format if JSON processing fails
      json output_obj;
      output_obj["id"] = failure.id;
      output_obj["error"] = {
        {"code", static_cast<int>(failure.status.code())},
        {"message", failure.status.message()},
        {"attempts", failure.attempts}
      };
      file << output_obj.dump() << "\n";
    }
  }
  file.close();
  std::cout << "Wrote " << failures_.size() << " failures to " 
            << failure_log_path_ << " in JSONL format" << std::endl;
  return absl::OkStatus();
}

}  // namespace privacy_sandbox::bidding_auction_servers
