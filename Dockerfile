FROM golang:1.25-alpine AS build

RUN apk add --no-cache ca-certificates

WORKDIR /src

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o /out/remirror .

RUN \
  mkdir -p /out/etc/ssl/certs/ && \
  cp  /etc/ssl/certs/ca-certificates.crt /out/etc/ssl/certs/

COPY remirror.hcl /out/remirror.hcl


FROM scratch

COPY --from=build /out/ /

EXPOSE 8080

ENTRYPOINT ["/remirror"]
