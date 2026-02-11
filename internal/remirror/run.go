package remirror

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"time"
)

// Run configures and starts the remirror server.
func Run(configPath string, enableVerbose bool) error {
	verbose = enableVerbose

	config := &Config{}
	if err := load_configs(config, configPath); err != nil {
		return fmt.Errorf("config error: %w", err)
	}
	if err := apply_env_overrides(config); err != nil {
		return fmt.Errorf("env override error: %w", err)
	}
	cacheRoot = config.Data

	// Initialize HTTP client with connection timeout (not total request timeout)
	connectTimeout := 30 * time.Second
	if config.UpstreamTimeout != "" {
		parsed, err := time.ParseDuration(config.UpstreamTimeout)
		if err != nil {
			return fmt.Errorf("invalid upstream_timeout value: %w", err)
		}
		connectTimeout = parsed
	}
	// Configure transport with dial timeout only, no overall request timeout
	http_client.Transport = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   connectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: connectTimeout,
		ExpectContinueTimeout: 1 * time.Second,
	}
	vlog("upstream connection timeout set to %v", connectTimeout)

	// Initialize metadata database for ETag storage
	if err := init_metadata_db(config.Data); err != nil {
		return fmt.Errorf("failed to initialize metadata database: %w", err)
	}
	defer metaDB.Close()
	vlog("metadata database initialized in %s", config.Data)

	// Start cache eviction scheduler if configured
	start_eviction_scheduler(config.Data, config.EvictOlderThan)

	fileserver := http.FileServer(http.Dir(config.Data))

	for _, mirror := range config.Mirrors {
		handler, err := mirror.CreateHandler(config, fileserver)
		if err == nil {
			log.Println(mirror, " ✓ ")
			http.Handle(mirror.Prefix, handler)
		} else {
			log.Println(mirror, " ✗ Error:", err)
		}
	}

	log.Println("remirror listening on HTTP", config.Listen, "with data cache", config.Data)
	return http.ListenAndServe(config.Listen, nil)
}
