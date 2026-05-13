FROM golang:1.23-alpine AS builder

ARG VERSION=dev

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=${VERSION}" -o /nostr-deadman .

FROM alpine:3.20
LABEL org.opencontainers.image.source=https://github.com/AusDavo/nostr-dead-man-switch
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /nostr-deadman /usr/local/bin/nostr-deadman
VOLUME /data
ENTRYPOINT ["nostr-deadman"]
CMD ["-config", "/data/config.yaml"]
