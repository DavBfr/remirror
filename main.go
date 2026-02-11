package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"time"

	_ "modernc.org/sqlite"
)

func main() {
	configPath := flag.String("config", "remirror.hcl", "Path to config file")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose logging")
	flag.Parse()
	verbose = *verboseFlag

	if flag.NArg() > 0 {
		log.Fatalf("Unhandled arguments: %v", flag.Args())
	}

	config := &Config{}

	if err := load_configs(config, *configPath); err != nil {
		log.Fatalf("Config error: %v", err)
	}
	if err := apply_env_overrides(config); err != nil {
		log.Fatalf("Env override error: %v", err)
	}
	cacheRoot = config.Data

	// Initialize HTTP client with connection timeout (not total request timeout)
	connectTimeout := 30 * time.Second // default timeout
	if config.UpstreamTimeout != "" {
		parsed, err := time.ParseDuration(config.UpstreamTimeout)
		if err != nil {
			log.Fatalf("Invalid upstream_timeout value: %v", err)
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
		log.Fatalf("Failed to initialize metadata database: %v", err)
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
	log.Fatal(http.ListenAndServe(config.Listen, nil))
}
