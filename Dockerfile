FROM golang:1.26-alpine@sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039 AS build

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
