#Build stage
FROM golang:1.23 AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o aegis main.go

#Runtime stage
FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/aegis /usr/local/bin/aegis
COPY --from=builder /app/certs /certs
EXPOSE 8080
CMD ["aegis"]
