# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Use a minimal Linux image
FROM ubuntu:latest

# Install necessary runtime dependencies
RUN apt update && \
     apt install -y  \
     jq \
     curl

WORKDIR /secure_invoke

# copy invoke binary and entrypoint script
COPY tools/secure_invoke/invoke .
COPY tools/secure_invoke/entrypoint.sh .

# copy dependent library
COPY external/cddl_lib/libcddl.so /lib

# Make executable
RUN chmod +x entrypoint.sh

# Use the entrypoint script instead of direct binary call
ENTRYPOINT ["/bin/bash", "entrypoint.sh"]

# Default command is empty, allowing arguments to be passed directly or from compose
CMD []
