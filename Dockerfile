FROM gcr.io/distroless/static:nonroot
ARG TARGETOS
ARG TARGETARCH
LABEL org.opencontainers.image.title="NetBird Operator" \
      org.opencontainers.image.description="Kubernetes operator for NetBird" \
      org.opencontainers.image.source="https://github.com/netbirdio/kubernetes-operator" \
      org.opencontainers.image.vendor="NetBird" \
      org.opencontainers.image.licenses="BSD-3-Clause"
COPY bin/${TARGETOS}-${TARGETARCH}/netbird-operator /usr/local/bin/
USER 65532:65532
ENTRYPOINT ["netbird-operator"]
