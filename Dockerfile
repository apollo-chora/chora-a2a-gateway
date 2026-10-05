# syntax=docker/dockerfile:1.6
#
# chora-a2a-gateway Dockerfile — standalone Go service.
#
# Build context = this repository. Shared Chora modules are resolved through
# Go modules (chora-common, chora-contracts), not a workspace.

ARG GO_VERSION=1.26.6
ARG ALPINE_VERSION=3.23
ARG SERVICE_NAME=chora-a2a-gateway
ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown

############################
# Stage 1 — build
############################
FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS builder

ARG SERVICE_NAME
ARG GIT_SHA
ARG BUILD_TIME

WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY . .

RUN go mod download

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64
RUN go build -trimpath \
      -ldflags "-s -w \
        -X main.gitSHA=${GIT_SHA} \
        -X main.buildTime=${BUILD_TIME}" \
      -o /out/service \
      ./cmd/server

############################
# Stage 2 — runtime
############################
FROM alpine:${ALPINE_VERSION}

ARG SERVICE_NAME
ARG GIT_SHA
ARG BUILD_TIME

RUN apk add --no-cache ca-certificates \
    && addgroup -S app \
    && adduser -S -G app app

LABEL org.opencontainers.image.title="${SERVICE_NAME}" \
      org.opencontainers.image.source="https://github.com/apollo-chora/chora-a2a-gateway" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_TIME}" \
      org.opencontainers.image.vendor="Chora Platform" \
      org.opencontainers.image.licenses="UNLICENSED" \
      io.chora.service="${SERVICE_NAME}" \
      io.chora.git-sha="${GIT_SHA}" \
      io.chora.build-time="${BUILD_TIME}"

WORKDIR /

COPY --from=builder /out/service /service

# Per-domain PII_Closure_Map.yaml (CHO-1719) — the federated closure-saga
# subscriber loads it at the default relative path
# config/PII_Closure_Map.yaml (runtime WORKDIR is /). Without this COPY
# the subscriber boots DISABLED (PII map load error).
COPY --from=builder /src/config/PII_Closure_Map.yaml /config/PII_Closure_Map.yaml

USER app:app
ENTRYPOINT ["/service"]
