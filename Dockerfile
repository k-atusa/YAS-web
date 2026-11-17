# syntax=docker/dockerfile:1

# Stage 1: Build frontend assets
FROM --platform=$BUILDPLATFORM node:26-alpine AS frontend-builder
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Build static Go binary with embedded frontend
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS backend-builder
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
COPY --from=frontend-builder /src/backend/internal/webui/static ./internal/webui/static
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -trimpath -o /out/yas-web ./cmd/server

# Stage 3: Minimal Alpine runtime image
FROM alpine:3.24 AS runtime
RUN apk add --no-cache ca-certificates && mkdir -p /app/data
WORKDIR /app
COPY --from=backend-builder /out/yas-web /app/yas-web

EXPOSE 4000
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${PORT:-4000}/api/health" || exit 1

ENTRYPOINT ["/app/yas-web"]
