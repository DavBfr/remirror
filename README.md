# remirror

Caching HTTP proxy for distro and toolchain mirrors. It sits in front of one or more upstream mirrors, streams responses to clients, and optionally caches matching artifacts on disk for future requests.

## Features

- Prefix-based routing to upstream mirrors or local directories.
- On-disk cache with concurrent download fanout (multiple clients can read a single in-progress download).
- Simple HCL configuration.
- Multiple upstreams per mirror with basic failover on 404/500/503.

## Build and run

You need a working Go installation (https://golang.org/doc/install).

```sh
go build .
./remirror
```

Flags:

- `--version` prints the current version and exits.

## Configuration

The server loads the first config file found in this order:

1. `./remirror.hcl`
2. `$HOME/.remirror.hcl`
3. `/etc/remirror.hcl`

Example configuration:

```hcl
listen = ":8084"
data = "/var/remirror"

mirrors {
    mirror {
        prefix = "/archlinux/"
        upstream = "https://mirrors.xmission.com"
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

- `listen`: HTTP bind address, e.g. `":8084"`.
- `data`: on-disk cache root, e.g. `"/var/remirror"`.
- `mirrors`: list of `mirror` blocks.

Each `mirror` supports:

- `prefix`: URL path prefix to match (required).
- `upstream`: single upstream base URL.
- `upstreams`: multiple upstream base URLs (used in order).
- `local`: local directory served instead of an upstream.
- `matches`: optional list of match rules to control caching behavior.

Match rules are evaluated in order and only apply when a rule matches both `prefix` and `suffix`:

- `prefix`: match start of the requested path.
- `suffix`: match end of the requested path.
- `skip`: when `true`, matching paths are not cached.

## Cache behavior

By default, remirror caches file types that look like archives or packages:
`.xz`, `.gz`, `.bz2`, `.zip`, `.tgz`, `.rpm`, `-rpm.bin`, `.deb`, `.jar`, `.xz.sig`.

Special-case exclusions:

- Debian/Ubuntu index files: `*/Packages.gz`, `*/Sources.gz`.
- Arch repo metadata: `*.abs.tar.gz`, `*.db.tar.gz`, `*.files.tar.gz`, `*.links.tar.gz`.

If `matches` is configured for a mirror, only matching rules are considered and the default list is ignored.

## Notes

- Range requests are proxied but are not cached.
- Failed upstream responses with 404/500/503 are retried against the next upstream in the list.

## See also

Ansible playbook: https://gitlab.com/ciphermail/debops.remirror
