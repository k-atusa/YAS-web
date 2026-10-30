# syntax=docker/dockerfile:1.8
FROM golang:1.27-bookworm AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/server ./cmd/server

FROM debian:bookworm-slim AS runner
WORKDIR /app
ENV PORT=7001
ENV DB_PATH=/app/data/yas-web.db

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /app/data

COPY --from=build /app/server ./server
RUN chmod +x ./server

EXPOSE 7001
CMD ["./server"]
