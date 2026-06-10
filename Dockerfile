FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod .
RUN go mod tidy
COPY . .
RUN GOOS=linux GOARCH=amd64 go build -o auth-service main.go

FROM alpine:3.14
WORKDIR /app
COPY --from=builder /app/auth-service .
EXPOSE 6969
CMD ["./auth-service"]
