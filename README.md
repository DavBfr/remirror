# remirror

Caching HTTP proxy for distro and toolchain mirrors. It sits in front of one or more upstream mirrors, streams responses to clients, and optionally caches matching artifacts on disk for future requests.

## Features

- Prefix-based routing to upstream mirrors or local directories.
- On-disk cache with concurrent download fanout (multiple clients can read a single in-progress download).
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
            match { pattern = "/(Packages|Sources)\\.gz$" skip = true }
            match { pattern = "\\.(abs|db|files|links)\\.tar\\.gz$" skip = true }
            match { pattern = "\\.(xz|gz|bz2|zip|tgz|rpm|deb|jar)$" }
            match { pattern = "-rpm\\.bin$" }
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
- `matches`: list of match rules that control caching behavior.

Match rules are evaluated in order and the first matching rule wins:

- `pattern`: Regular expression pattern to match against the request path.
- `skip`: when `true`, matching paths are not cached.

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
- `MATCHES` (comma-separated list of `pattern[:skip]` entries)

Example:

```sh
export REMIRROR_LISTEN=":8080"
export REMIRROR_DATA="/var/remirror"
export REMIRROR_MIRRORS_ARCH_PREFIX="/archlinux/"
export REMIRROR_MIRRORS_ARCH_UPSTREAMS="https://mirror1.example.com,https://mirror2.example.com"
export REMIRROR_MIRRORS_ARCH_MATCHES='\\.pkg\\.tar\\.zst$,\\.sig$'
```

## Cache behavior

Caching is driven entirely by `matches` regular expressions. If a mirror has no match rules, nothing is cached for that mirror. Rules are evaluated in order and the first matching rule wins.

The default [remirror.hcl](remirror.hcl) includes patterns that:
- Skip repo metadata (such as `*/Packages.gz` and `*.db.tar.gz`).
- Cache common archive and package formats (`.xz`, `.rpm`, `.deb`, etc).

## Notes

- Range requests are proxied but are not cached.
- Failed upstream responses with 404/500/503 are retried against the next upstream in the list.

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
