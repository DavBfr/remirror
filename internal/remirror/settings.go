package remirror

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
)

type Config struct {
	Listen          string   `hcl:"listen"`
	Data            string   `hcl:"data"`
	Host            string   `hcl:"host"`
	EvictOlderThan  string   `hcl:"evict_older_than"`
	UpstreamTimeout string   `hcl:"upstream_timeout"`
	Mirrors         []Mirror `hcl:"mirrors"`
}

func split_csv(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}

func apply_env_overrides(config *Config) error {
	if v := strings.TrimSpace(os.Getenv("REMIRROR_LISTEN")); v != "" {
		config.Listen = v
	}
	if v := strings.TrimSpace(os.Getenv("REMIRROR_DATA")); v != "" {
		config.Data = v
	}
	if v := strings.TrimSpace(os.Getenv("REMIRROR_HOST")); v != "" {
		config.Host = v
	}
	if v := strings.TrimSpace(os.Getenv("REMIRROR_EVICT_OLDER_THAN")); v != "" {
		config.EvictOlderThan = v
	}
	if v := strings.TrimSpace(os.Getenv("REMIRROR_UPSTREAM_TIMEOUT")); v != "" {
		config.UpstreamTimeout = v
	}

	mirrorsByName := map[string]*Mirror{}

	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		val := strings.TrimSpace(parts[1])
		const prefix = "REMIRROR_MIRRORS_"
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		rest := strings.TrimPrefix(key, prefix)
		nameField := strings.SplitN(rest, "_", 2)
		if len(nameField) != 2 {
			continue
		}
		name := nameField[0]
		field := nameField[1]
		if name == "" || field == "" {
			continue
		}

		mirror := mirrorsByName[name]
		if mirror == nil {
			mirror = &Mirror{}
			mirrorsByName[name] = mirror
		}

		switch field {
		case "PREFIX":
			mirror.Prefix = val
		case "UPSTREAM":
			mirror.Upstream = val
		case "UPSTREAMS":
			mirror.Upstreams = split_csv(val)
		case "LOCAL":
			mirror.Local = val
		case "MATCHES":
			matches, err := parse_matches(val)
			if err != nil {
				return err
			}
			mirror.Matches = matches
		default:
			log.Printf("Ignoring unknown env field %s for mirror %s", field, name)
		}
	}

	if len(mirrorsByName) == 0 {
		return nil
	}

	names := make([]string, 0, len(mirrorsByName))
	for name := range mirrorsByName {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		src := mirrorsByName[name]
		if src.Prefix == "" {
			log.Printf("Skipping mirror %s: PREFIX is required", name)
			continue
		}
		applied := false
		for i := range config.Mirrors {
			if config.Mirrors[i].Prefix == src.Prefix {
				override_mirror(&config.Mirrors[i], src)
				if err := compile_mirror_matches(&config.Mirrors[i]); err != nil {
					return fmt.Errorf("Env mirror %s: %w", src.Prefix, err)
				}
				applied = true
				break
			}
		}
		if !applied {
			if err := compile_mirror_matches(src); err != nil {
				return fmt.Errorf("Env mirror %s: %w", src.Prefix, err)
			}
			config.Mirrors = append(config.Mirrors, *src)
		}
	}

	return nil
}
