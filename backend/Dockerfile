FROM golang:1.22-alpine AS build

WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY go.mod ./
RUN go mod download

COPY . .

RUN go build -o /usr/local/bin/sentracore ./cmd/sentracore

FROM alpine:3.19

WORKDIR /app
RUN apk add --no-cache ca-certificates

COPY --from=build /usr/local/bin/sentracore /usr/local/bin/sentracore
COPY sql ./sql
COPY config ./config

ENV SENTRACORE_HTTP_ADDR=":8080"

EXPOSE 8080

CMD ["sentracore"]
