FROM golang:1.21-alpine AS builder
WORKDIR /app
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -a -installsuffix cgo -o jsyproxy .

FROM alpine:latest
RUN apk --no-cache add ca-certificates wget su-exec && \
    adduser -D -H -h /app -u 1000 appuser && \
    mkdir -p /app/data && \
    chown -R appuser:appuser /app
WORKDIR /app
COPY --from=builder /app/jsyproxy .
COPY docker-entrypoint.sh .
RUN chmod +x /app/jsyproxy /app/docker-entrypoint.sh
VOLUME /app/data
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --spider -q http://localhost:3000/admin || exit 1
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["./jsyproxy"]
