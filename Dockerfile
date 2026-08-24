FROM golang:1.27-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build

RUN apk add --no-cache ca-certificates

WORKDIR /src

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o /out/remirror ./cmd/remirror

RUN \
  mkdir -p /out/etc/ssl/certs/ && \
  cp  /etc/ssl/certs/ca-certificates.crt /out/etc/ssl/certs/

COPY remirror.hcl /out/remirror.hcl


FROM scratch

COPY --from=build /out/ /

EXPOSE 8080

ENTRYPOINT ["/remirror"]
