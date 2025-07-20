FROM envoyproxy/envoy:distroless-dev-1e68b78b9f26e4d93b01faae257158b3ec54798a AS envoy
FROM  bazel/production/packaging/gcp/buyer_frontend_service:server_docker_image AS final
COPY --from=envoy /usr/local/bin/envoy /usr/local/bin/envoy
COPY envoy.yaml /etc/envoy/envoy.yaml
COPY bidding_auction_servers_descriptor_set.pb /etc/envoy
COPY init_server_basic /server/bin
CMD [ "/server/bin/init_server_basic" ]                             