FROM golang:1.23-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /nostr-deadman .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /nostr-deadman /usr/local/bin/nostr-deadman
VOLUME /data
ENTRYPOINT ["nostr-deadman"]
CMD ["-config", "/data/config.yaml"]
