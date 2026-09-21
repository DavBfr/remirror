FROM golang:1.27-alpine@sha256:4cb7ac979db5fcc41cae44b2227ba5ab8a51e8807f40d9ba4dee20a0ad960b5b AS build

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
