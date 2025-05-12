# Use a minimal Linux image
FROM ubuntu:latest

# Install necessary runtime dependencies
 RUN apt update && \
     apt install -y  \
     #libssl1.1 \
     #libcurl4 \
     #ca-certificates \
     #busybox \
     jq \
     curl 
     
# Copy entrypoint script
#COPY tools/secure_invoke.tar .

# Extract the tarball
#RUN tar -xf secure_invoke.tar

#RUN rm -rf secure_invoke.tar

WORKDIR /secure_invoke

COPY tools/secure_invoke/invoke .
COPY tools/secure_invoke/entrypoint.sh .

COPY external/cddl_lib/libcddl.so /lib

# Make executable
RUN chmod +x entrypoint.sh

# Use the entrypoint script instead of direct binary call
ENTRYPOINT ["/bin/bash", "entrypoint.sh"]

# Default command is empty, allowing arguments to be passed directly or from compose
CMD []
