# Builder Stage
FROM golang:1.23.4 as builder

WORKDIR /app

# Copy files
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Inject BuildDate Metadata
ARG BUILD_DATE
RUN go build -ldflags="-X 'accesscontrolapi/internal/version.BuildDate=${BUILD_DATE}'" -o accesscontrolapi .
# Final Stage
FROM debian:bookworm-slim
# Install CA certificates
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/accesscontrolapi .

RUN chmod +x ./accesscontrolapi

EXPOSE 8080

CMD ["./accesscontrolapi"]
# CMD ["tail", "-f", "/dev/null"]
