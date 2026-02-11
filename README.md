# remirror

Caching HTTP proxy for distro and toolchain mirrors. It sits in front of one or more upstream mirrors, streams responses to clients, and optionally caches matching artifacts on disk for future requests.

## Features

- Prefix-based routing to upstream mirrors or local directories.
- On-disk cache with concurrent download fanout (multiple clients can read a single in-progress download).
- Automatic cache validation using `If-Modified-Since` headers.
- Resilient operation: serves from cache when upstream is unavailable.
- HCL configuration with env overrides.
- Multiple upstreams per mirror with basic failover on 404/500/503.

## Build and run

You need a working Go installation (<https://golang.org/doc/install>).

```sh
go build .
./remirror
```

Flags:

- `--version` prints the current version and exits.
- `-config` sets the config file path (defaults to `remirror.hcl`).

## Configuration

By default the server loads `remirror.hcl` from the current working directory. You can override the path with `-config`.

Example configuration:

```hcl
listen = ":8080"
data = "/var/remirror"

mirrors {
    mirror {
        prefix = "/archlinux/"
        upstream = "https://mirrors.xmission.com"
        matches {
            match { pattern = "/(Packages|Sources)\\.gz$" action = "try" }
            match { pattern = "\\.(db|files|links)\\.tar\\.gz$" action = "try" }
        }
    }

    mirror {
        prefix = "/centos/"
        upstream = "https://mirrors.xmission.com"
    }

    mirror {
        prefix = "/fedora/"
        upstream = "https://mirrors.xmission.com"
    }

    mirror {
        prefix = "/fedora-epel/"
        upstream = "https://mirrors.xmission.com"
    }

    mirror {
        prefix = "/golang/"
        upstream = "https://storage.googleapis.com"
    }
}
```

### Config fields

- `listen`: HTTP bind address, e.g. `":8080"`.
- `data`: on-disk cache root, e.g. `"/var/remirror"`.
- `mirrors`: list of `mirror` blocks.

Each `mirror` supports:

- `prefix`: URL path prefix to match (required).
- `upstream`: single upstream base URL.
- `upstreams`: multiple upstream base URLs (used in order).
- `local`: local directory served instead of an upstream.
- `matches`: optional list of match rules to control cache behavior.

Match rules control caching behavior with three possible actions:

- `pattern`: Regular expression pattern to match against the request path.
- `action`: Cache behavior for matching paths:
  - `"cache"` (default): Cache forever without validation
  - `"try"`: Cache but validate with `If-Modified-Since` on every request
  - `"skip"`: Never cache, always proxy directly from upstream

### Environment overrides

Environment variables override values loaded from the HCL file. Mirrors defined in env are merged into the HCL mirror list. If an env mirror has the same `prefix` as an HCL mirror, it overrides that mirror's fields.

Top-level overrides:

- `REMIRROR_LISTEN`
- `REMIRROR_DATA`

Mirror overrides use the pattern `REMIRROR_MIRRORS_<name>_<FIELD>`.

Supported fields:

- `PREFIX` (required)
- `UPSTREAM`
- `UPSTREAMS` (comma-separated list)
- `LOCAL`
- `MATCHES` (comma-separated list of `pattern[:action]` entries, where action is `cache`, `try`, or `skip`)

Example:

```sh
export REMIRROR_LISTEN=":8080"
export REMIRROR_DATA="/var/remirror"
export REMIRROR_MIRRORS_ARCH_PREFIX="/archlinux/"
export REMIRROR_MIRRORS_ARCH_UPSTREAMS="https://mirror1.example.com,https://mirror2.example.com"
export REMIRROR_MIRRORS_ARCH_MATCHES='\\.pkg\\.tar\\.zst$:cache,\\.sig$:try'
```

## Cache behavior

Caching behavior is controlled by match rules with three actions:

- **`action = "cache"` (default)**: Files are cached forever once downloaded. Subsequent requests are served directly from cache without contacting upstream.

- **`action = "try"`**: Files are cached but validated with `If-Modified-Since` on every request. If upstream returns `304 Not Modified`, the cached version is served. If upstream is unreachable, the cache is still served.

- **`action = "skip"`**: Files are never cached. Every request is proxied directly to upstream without storing on disk.

This allows package archives and immutable content to be cached permanently (action="cache"), while repo metadata (like `Packages.gz`) stays fresh (action="try"), and sensitive or dynamic content is never stored (action="skip").

The default [remirror.hcl](remirror.hcl) includes `action = "try"` patterns for repo metadata that should always be validated.

## Notes

- Files without matching rules default to `action = "cache"` (cached forever).
- Files with `action = "try"` are cached but validated with `If-Modified-Since` on every request.
- Files with `action = "skip"` are never cached and always proxied to upstream.
- When upstream mirrors are unreachable or return errors, cached versions are served automatically (for "cache" and "try" actions).
- Range requests are served directly from cache without revalidation.
- Failed upstream responses with 404/500/503 fall back to cache if available, or retry the next upstream.

## Docker

Build and run locally:

```sh
docker build -t remirror .
docker run --rm -p 8080:8080 -v remirror-data:/var/remirror remirror
```

Compose:

```sh
docker compose up
```
