package main

import (
	"database/sql"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/hcl"
	_ "modernc.org/sqlite"
)

const VERSION = "0.0.6"

type Config struct {
	Listen  string // HTTP listen address. ":8080"
	Data    string // Storage location for cached files. "/var/remirror"
	Mirrors []Mirror
}
type Mirror struct {
	// Prefix specifies a path that should be sent
	// to a certain upstream. E.g. "/archlinux/"
	Prefix string

	// Upstream specifies the upstream protocol and host.
	// You may also specify a path, in which case Prefix is
	// stripped from the incoming request, and what is left is
	// appended to the upstream path component.
	//
	// E.g. "https://mirrors.kernel.org"     (/archlinux/somepackage will be preserved)
	// E.g. "http://mirror.cs.umn.edu/arch/" (/archlinux/thing will transform to /arch/thing)
	Upstream string

	// Upstreams specifies multiple Upstream entries. You can specify both (all will be used).
	Upstreams []string

	// Local should be used instead of Upstream for a locally served folder.
	// Incoming requests will have Prefix stripped off before being sent to Local.
	// E.g. "/home/you/localrepos/archlinux"
	Local string

	// If empty, nothing will be cached for this mirror
	Matches []Match

	// Compiled regexes for matches, populated after config load
	compiledMatches []*compiledMatch
}

type Match struct {
	Pattern string // Regular expression pattern
	Action  string // action = "cache" (default), "try" (cache with revalidation), or "skip" (don't cache)
}

type compiledMatch struct {
	regex  *regexp.Regexp
	action string
}

func (mirror Mirror) String() string {
	s := mirror.Local
	if s == "" {
		count := 0
		if mirror.Upstream != "" {
			s = mirror.Upstream
			count++
		}
		if s == "" && len(mirror.Upstreams) > 0 {
			s = mirror.Upstreams[0]
		}
		count += len(mirror.Upstreams)
		if count > 1 {
			s += fmt.Sprintf(" (+ %d more...)", count-1)
		}
	}
	s += " "
	for i, m := range mirror.Matches {
		ss := m.Pattern
		if m.Action != "" && m.Action != "cache" {
			ss += " " + m.Action
		}
		if i+1 < len(mirror.Matches) {
			ss += ", "
		}
		s += ss
	}
	return fmt.Sprintf("%-20s » %s", mirror.Prefix, s)
}

var (
	http_client = http.Client{}
	metaDB      *sql.DB
	verbose     bool

	downloads_mu sync.Mutex
	downloads    = map[string]*Download{}
)

func vlog(format string, args ...interface{}) {
	if verbose {
		log.Printf(format, args...)
	}
}

func vlog_headers(prefix string, headers http.Header) {
	if !verbose {
		return
	}
	for k, vs := range headers {
		vlog("%s %s: %s", prefix, k, strings.Join(vs, ", "))
	}
}

func set_cache_metadata_headers(w http.ResponseWriter, etag, lastModified string) {
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	if lastModified != "" {
		w.Header().Set("Last-Modified", lastModified)
	}
}

func etag_matches(headerValue, etag string) bool {
	if headerValue == "*" {
		return true
	}
	for _, part := range strings.Split(headerValue, ",") {
		if strings.TrimSpace(part) == etag {
			return true
		}
	}
	return false
}

func handle_client_conditionals(w http.ResponseWriter, r *http.Request, local_path string, fileInfo os.FileInfo) bool {
	etag, lastModified, metaErr := get_metadata(local_path)
	if metaErr != nil {
		vlog("conditional metadata lookup failed for %s: %v", local_path, metaErr)
	}
	if lastModified == "" {
		lastModified = fileInfo.ModTime().UTC().Format(http.TimeFormat)
	}

	if inm := r.Header.Get("If-None-Match"); inm != "" && etag != "" {
		if etag_matches(inm, etag) {
			vlog("conditional If-None-Match hit for %s", local_path)
			set_cache_metadata_headers(w, etag, lastModified)
			w.Header().Set("Server", "remirror")
			w.WriteHeader(http.StatusNotModified)
			return true
		}
	}

	if ims := r.Header.Get("If-Modified-Since"); ims != "" {
		if imsTime, err := http.ParseTime(ims); err == nil {
			modTime := fileInfo.ModTime().UTC()
			if lmTime, lmErr := http.ParseTime(lastModified); lmErr == nil {
				modTime = lmTime.UTC()
			}
			if !modTime.After(imsTime) {
				vlog("conditional If-Modified-Since hit for %s", local_path)
				set_cache_metadata_headers(w, etag, lastModified)
				w.Header().Set("Server", "remirror")
				w.WriteHeader(http.StatusNotModified)
				return true
			}
		}
	}

	return false
}

func serve_cached(w http.ResponseWriter, r *http.Request, local_path string, fileInfo os.FileInfo, fileserver http.Handler) {
	if handle_client_conditionals(w, r, local_path, fileInfo) {
		return
	}
	etag, lastModified, _ := get_metadata(local_path)
	if lastModified == "" {
		lastModified = fileInfo.ModTime().UTC().Format(http.TimeFormat)
	}
	set_cache_metadata_headers(w, etag, lastModified)
	fileserver.ServeHTTP(w, r)
}

type Download struct {
	resp *http.Response

	tmp_path string
	tmp_done chan struct{} // will be closed when download is done and final bytes written
}

func (mirror Mirror) should_skip(path string) bool {
	// Don't cache files matching action="skip" patterns
	for _, cm := range mirror.compiledMatches {
		if cm.regex.MatchString(path) && cm.action == "skip" {
			vlog("skip action matched for %s", path)
			return true
		}
	}
	return false
}

func (mirror Mirror) should_revalidate(path string) bool {
	// Revalidate files matching action="try" patterns
	for _, cm := range mirror.compiledMatches {
		if cm.regex.MatchString(path) && cm.action == "try" {
			vlog("try action matched for %s", path)
			return true
		}
	}
	return false
}

// proxy_request forwards a request directly to upstream without caching
func proxy_request(w http.ResponseWriter, r *http.Request, remote_url string) error {
	vlog("proxying without cache: %s", remote_url)
	req, err := http.NewRequest("GET", remote_url, nil)
	if err != nil {
		return err
	}

	// Copy headers from original request
	for k, vs := range r.Header {
		if !hopHeaders[k] {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
	}
	vlog_headers("proxy request", req.Header)

	resp, err := http_client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	vlog("proxy response %d for %s", resp.StatusCode, remote_url)
	vlog_headers("proxy response", resp.Header)

	// Copy response headers
	for k, vs := range resp.Header {
		if k == "Accept-Ranges" {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}

	w.Header().Set("Server", "remirror")
	w.WriteHeader(resp.StatusCode)

	// Stream response body
	_, err = io.Copy(w, resp.Body)
	return err
}

func (mirror Mirror) CreateHandler(config *Config, fileserver http.Handler) (http.Handler, error) {

	if mirror.Local != "" {
		return http.StripPrefix(mirror.Prefix, http.FileServer(http.Dir(mirror.Local))), nil
	}

	upstreams := []*url.URL{}

	if mirror.Upstream != "" {
		upstream, err := url.Parse(mirror.Upstream)
		if err != nil {
			return nil, err
		}
		upstreams = append(upstreams, upstream)
	}
	for _, u := range mirror.Upstreams {
		upstream, err := url.Parse(u)
		if err != nil {
			return nil, err
		}
		upstreams = append(upstreams, upstream)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Method + " http://" + r.Host + r.RequestURI)

		err := func() error {

			for _, upstream := range upstreams {

				local_path := ""
				remote_url := upstream.Scheme + "://" + upstream.Host

				// Ugh... This is not the right way to do this.
				// I'm not sure how to make it encode + to %,
				// while not encoding /
				remote_url = strings.Replace(remote_url, "+", "%2B", -1)

				if upstream.Path == "" {
					remote_url += path.Clean(r.URL.Path)
				} else {
					remote_url += path.Clean(upstream.Path + "/" + strings.TrimPrefix(r.URL.Path, mirror.Prefix))
				}

				vlog("resolved upstream url: %s", remote_url)

				// Check if this should never be cached
				if mirror.should_skip(remote_url) {
					// Don't cache, proxy directly
					if err := proxy_request(w, r, remote_url); err != nil {
						vlog("proxy error for %s: %v", remote_url, err)
					}
					return nil
				}

				local_path = config.Data + path.Clean(r.URL.Path)

				// Check if we have a cached version
				fileInfo, err := os.Stat(local_path)
				if err == nil {
					vlog("cache hit: %s", local_path)
					// We have a cached file
					if mirror.should_revalidate(remote_url) {
						// Revalidate files matching action="try" patterns
						if revalidate_cache(w, r, local_path, fileInfo, remote_url, fileserver) {
							return nil
						}
						// Revalidation indicated we need to download
					} else {
						// Cache forever - serve directly
						serve_cached(w, r, local_path, fileInfo, fileserver)
						return nil
					}
				}

				var download *Download
				var ok bool

				downloads_mu.Lock()

				if r.Header.Get("Range") == "" && local_path != "" {
					download, ok = downloads[local_path]
					if ok {
						vlog("waiting on in-progress download: %s", local_path)
						fh, err := os.Open(download.tmp_path)
						downloads_mu.Unlock()
						if err != nil {
							return err
						}
						return tmp_download(local_path, w, download, fh)
					}
				}

				// downloads_mu is still locked. take care.
				// we need to keep it locked until we have
				// registered a download, opened a temp file,
				// and saved it's path into the tmp_path in
				// the struct.
				// then we need to make sure to release.

				log.Println("-->", remote_url)

				req, err := http.NewRequest("GET", remote_url, nil)
				if err != nil {
					downloads_mu.Unlock()
					// If we have a cached version, serve it despite the error
					if local_path != "" {
						if _, statErr := os.Stat(local_path); statErr == nil {
							log.Printf("Remote error, serving from cache: %v", err)
							fileserver.ServeHTTP(w, r)
							return nil
						}
					}
					return err
				}

				for k, vs := range r.Header {
					if !hopHeaders[k] {
						for _, v := range vs {
							req.Header.Add(k, v)
						}
					}
				}
				vlog_headers("upstream request", req.Header)

				resp, err := http_client.Do(req)
				if err != nil {
					downloads_mu.Unlock()
					vlog("upstream request failed: %v", err)
					// If we have a cached version, serve it despite the error
					if local_path != "" {
						if cachedInfo, statErr := os.Stat(local_path); statErr == nil {
							log.Printf("Remote error, serving from cache: %v", err)
							serve_cached(w, r, local_path, cachedInfo, fileserver)
							return nil
						}
					}
					return err
				}
				defer resp.Body.Close()
				vlog("upstream response %d for %s", resp.StatusCode, remote_url)
				vlog_headers("upstream response", resp.Header)

				// Try another mirror if we get certain status codes
				if resp.StatusCode == 404 ||
					resp.StatusCode == 500 ||
					resp.StatusCode == 503 {
					vlog("upstream returned %d for %s", resp.StatusCode, remote_url)
					downloads_mu.Unlock()
					// If we have a cached version and got 404/500/503, serve from cache
					if local_path != "" && resp.StatusCode != 404 {
						if cachedInfo, statErr := os.Stat(local_path); statErr == nil {
							log.Printf("Remote returned %d, serving from cache", resp.StatusCode)
							serve_cached(w, r, local_path, cachedInfo, fileserver)
							return nil
						}
					}
					continue
				}

				out := io.Writer(w)

				tmp_path := ""

				var tmp_needs_final_close io.Closer

				// We don't want to cache the result if the server
				// returns with a 206 Partial Content
				if resp.StatusCode == 200 && local_path != "" {
					vlog("downloading to cache: %s", local_path)
					tmp, err := ioutil.TempFile(config.Data, "remirror_tmp_")
					if err != nil {
						downloads_mu.Unlock()
						return err
					}
					tmp_needs_final_close = tmp
					tmp_path = tmp.Name()
					//fmt.Println("tmp", tmp_path)

					defer tmp.Close()
					defer os.Remove(tmp_path)

					out = io.MultiWriter(out, tmp)

					// at this point we have a "successful" download in
					// progress. save into the struct.
					download = &Download{
						resp:     resp,
						tmp_path: tmp_path,
						tmp_done: make(chan struct{}),
					}
					downloads[local_path] = download
				}
				// release the mutex. if we have a successful download in
				// progress, we have stored it correctly so far. if not,
				// we unlock, leaving the download struct unmodified. the
				// next request to try that URL will retry.
				downloads_mu.Unlock()

				// however we quit, we want to clear the download in progress
				// entry. this deferred func should run before the deferred
				// cleanup funcs above, so the filehandle should still be
				// valid when we clear it out.
				defer func() {
					if download == nil {
						// we didn't end up using the map for some reason.
						// (maybe empty content length, non 200 response, etc)
						return
					}

					// make sure final close has been called. things might still
					// be writing, and we need that to be done before
					// we close tmp_done
					_ = tmp_needs_final_close.Close()

					close(download.tmp_done)

					downloads_mu.Lock()
					delete(downloads, local_path)
					downloads_mu.Unlock()
				}()

				write_resp_headers(w, resp)
				vlog("upstream response %d for %s", resp.StatusCode, remote_url)

				n, err := io.Copy(out, resp.Body)
				if err != nil {
					log.Println(err)
					return nil
				}

				if n != resp.ContentLength && resp.ContentLength != -1 {
					log.Printf("Short data returned from server (Content-Length %d received %d)\n", resp.ContentLength, n)

					// Not really an HTTP error, leave it up to the client.
					// but we aren't going to save our response to the cache.
					return nil
				}

				if tmp_path != "" {
					os.MkdirAll(path.Dir(local_path), 0755)

					err = tmp_needs_final_close.Close()
					if err != nil {
						log.Println(err)
						return nil
					}

					// clear from struct before renaming
					if download != nil {
						close(download.tmp_done)
						downloads_mu.Lock()
						delete(downloads, local_path)
						downloads_mu.Unlock()
						download = nil // so we don't re-close
					}

					err = os.Rename(tmp_path, local_path)
					if err != nil {
						log.Println(err)
						return nil
					}

					// Store ETag and Last-Modified
					etag := resp.Header.Get("ETag")
					lastModified := resp.Header.Get("Last-Modified")
					if lastModified == "" {
						if info, statErr := os.Stat(local_path); statErr == nil {
							lastModified = info.ModTime().UTC().Format(http.TimeFormat)
						}
					}
					if lastModified == "" {
						lastModified = time.Now().UTC().Format(http.TimeFormat)
					}
					vlog("storing metadata for %s (etag=%q, last_modified=%q)", local_path, etag, lastModified)
					if err := store_metadata(local_path, etag, lastModified); err != nil {
						log.Printf("Warning: failed to store metadata: %v", err)
					}

					log.Println(">:)")
				}

				return nil

			}

			return HTTPError(404)

		}()

		he, ok := err.(HTTPError)
		if ok {
			http.Error(w, he.Error(), he.Code())
			fmt.Println("\t\t", he.Error())
		} else if err != nil {
			http.Error(w, err.Error(), 500)
			fmt.Println("\t\t500 " + err.Error())
		}
	}), nil
}

func load_configs(config *Config, configPath string) error {
	log.Printf("Loading configuration from %#v ...\n", configPath)
	configBytes, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("Config error: unable to read %s: %w", configPath, err)
	}
	if err := hcl.Unmarshal(configBytes, config); err != nil {
		return err
	}
	// Compile regex patterns
	for i := range config.Mirrors {
		if err := compile_mirror_matches(&config.Mirrors[i]); err != nil {
			return fmt.Errorf("Mirror %s: %w", config.Mirrors[i].Prefix, err)
		}
	}
	return nil
}

// revalidate_cache checks if the cached file is still valid using ETag or If-Modified-Since
// Returns true if the request was handled (either 304 or served from cache)
func revalidate_cache(w http.ResponseWriter, r *http.Request, local_path string, fileInfo os.FileInfo, remote_url string, fileserver http.Handler) bool {
	// Don't revalidate on Range requests
	if r.Header.Get("Range") != "" {
		fileserver.ServeHTTP(w, r)
		return true
	}

	req, err := http.NewRequest("GET", remote_url, nil)
	if err != nil {
		// If we can't create the request, serve from cache
		log.Printf("Error creating revalidation request, serving from cache: %v", err)
		serve_cached(w, r, local_path, fileInfo, fileserver)
		return true
	}

	// Try to use ETag and Last-Modified if we have them stored
	etag, lastModified, metaErr := get_metadata(local_path)
	if metaErr == nil && etag != "" {
		req.Header.Set("If-None-Match", etag)
		vlog("revalidate ETag for %s: %s", local_path, etag)
	} else if metaErr != nil {
		vlog("revalidate metadata lookup failed for %s: %v", local_path, metaErr)
	} else {
		vlog("no stored ETag for %s", local_path)
	}

	// Add If-Modified-Since header as fallback
	ims := lastModified
	if ims == "" {
		ims = fileInfo.ModTime().UTC().Format(http.TimeFormat)
	}
	req.Header.Set("If-Modified-Since", ims)
	vlog("revalidate If-Modified-Since for %s: %s", local_path, ims)
	vlog_headers("revalidate request", req.Header)

	// Copy original request headers
	for k, vs := range r.Header {
		if !hopHeaders[k] {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
	}

	resp, err := http_client.Do(req)
	if err != nil {
		// Network error, serve from cache
		log.Printf("Remote unreachable during revalidation, serving from cache: %v", err)
		serve_cached(w, r, local_path, fileInfo, fileserver)
		return true
	}
	defer resp.Body.Close()
	vlog("revalidate response %d for %s", resp.StatusCode, remote_url)
	vlog_headers("revalidate response", resp.Header)

	if resp.StatusCode == 304 {
		// Not modified, serve from cache
		log.Printf("Cache hit (304): %s", local_path)
		serve_cached(w, r, local_path, fileInfo, fileserver)
		return true
	}

	if resp.StatusCode == 200 {
		// File was modified, we need to update it
		// Return false so the main handler downloads it
		log.Printf("Cache stale (200): %s", local_path)
		return false
	}

	if resp.StatusCode >= 500 {
		// Server error, serve from cache
		log.Printf("Remote error %d during revalidation, serving from cache", resp.StatusCode)
		serve_cached(w, r, local_path, fileInfo, fileserver)
		return true
	}

	if resp.StatusCode == 404 {
		// File no longer exists upstream, but we have it cached
		// Serve from cache anyway
		log.Printf("File not found upstream (404), serving from cache: %s", local_path)
		serve_cached(w, r, local_path, fileInfo, fileserver)
		return true
	}

	// For other status codes, serve from cache
	log.Printf("Unexpected status %d during revalidation, serving from cache", resp.StatusCode)
	serve_cached(w, r, local_path, fileInfo, fileserver)
	return true
}

func compile_mirror_matches(mirror *Mirror) error {
	mirror.compiledMatches = make([]*compiledMatch, 0, len(mirror.Matches))
	for i, m := range mirror.Matches {
		if m.Pattern == "" {
			return fmt.Errorf("Match rule %d has empty pattern", i)
		}
		re, err := regexp.Compile(m.Pattern)
		if err != nil {
			return fmt.Errorf("Match rule %d pattern %q: %w", i, m.Pattern, err)
		}
		action := m.Action
		if action == "" {
			action = "cache" // default action
		}
		if action != "cache" && action != "try" && action != "skip" {
			return fmt.Errorf("Match rule %d has invalid action %q (must be cache, try, or skip)", i, action)
		}
		mirror.compiledMatches = append(mirror.compiledMatches, &compiledMatch{
			regex:  re,
			action: action,
		})
	}
	return nil
}

func apply_env_overrides(config *Config) error {
	if v := strings.TrimSpace(os.Getenv("REMIRROR_LISTEN")); v != "" {
		config.Listen = v
	}
	if v := strings.TrimSpace(os.Getenv("REMIRROR_DATA")); v != "" {
		config.Data = v
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

func override_mirror(dst *Mirror, src *Mirror) {
	if src.Prefix != "" {
		dst.Prefix = src.Prefix
	}
	if src.Upstream != "" {
		dst.Upstream = src.Upstream
	}
	if len(src.Upstreams) > 0 {
		dst.Upstreams = src.Upstreams
	}
	if src.Local != "" {
		dst.Local = src.Local
	}
	if len(src.Matches) > 0 {
		dst.Matches = src.Matches
	}
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

func parse_matches(value string) ([]Match, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	entries := strings.Split(value, ",")
	matches := make([]Match, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.Split(entry, ":")
		if len(parts) < 1 || len(parts) > 2 {
			return nil, fmt.Errorf("Invalid match entry %q (expected pattern[:action])", entry)
		}
		m := Match{
			Pattern: parts[0],
		}
		if len(parts) == 2 {
			action := parts[1]
			if action != "cache" && action != "try" && action != "skip" {
				return nil, fmt.Errorf("Invalid action %q in match entry (must be cache, try, or skip)", action)
			}
			m.Action = action
		}
		matches = append(matches, m)
	}
	return matches, nil
}

// init_metadata_db initializes the SQLite database for storing ETags
func init_metadata_db(dataPath string) error {
	dbPath := path.Join(dataPath, "metadata.db")

	// Ensure the data directory exists
	if err := os.MkdirAll(dataPath, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Create the metadata table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS etags (
			path TEXT PRIMARY KEY,
			etag TEXT NOT NULL,
			last_modified DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)
	`)
	if err != nil {
		db.Close()
		return fmt.Errorf("failed to create etags table: %w", err)
	}

	metaDB = db
	return nil
}

// store_metadata saves ETag and Last-Modified for a given file path
func store_metadata(filePath, etag, lastModified string) error {
	if metaDB == nil {
		return fmt.Errorf("metadata database not initialized")
	}

	// Avoid updating updated_at when metadata hasn't changed.
	var existingEtag string
	var existingLastModified string
	err := metaDB.QueryRow(`SELECT etag, last_modified FROM etags WHERE path = ?`, filePath).Scan(&existingEtag, &existingLastModified)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if lastModified == "" {
		lastModified = existingLastModified
	}
	if lastModified == "" {
		lastModified = time.Now().UTC().Format(http.TimeFormat)
	}
	if err == nil && existingEtag == etag && existingLastModified == lastModified {
		vlog("metadata unchanged for %s", filePath)
		return nil
	}

	if err == nil {
		vlog("metadata updated for %s: etag %q -> %q, last_modified %q -> %q", filePath, existingEtag, etag, existingLastModified, lastModified)
	} else {
		vlog("metadata inserted for %s: etag %q, last_modified %q", filePath, etag, lastModified)
	}

	_, err = metaDB.Exec(
		`INSERT OR REPLACE INTO etags (path, etag, last_modified, updated_at) VALUES (?, ?, ?, ?)`,
		filePath, etag, lastModified, time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// get_metadata retrieves stored ETag and Last-Modified for a given file path
func get_metadata(filePath string) (string, string, error) {
	if metaDB == nil {
		return "", "", fmt.Errorf("metadata database not initialized")
	}

	var etag string
	var lastModified string
	err := metaDB.QueryRow(`SELECT etag, last_modified FROM etags WHERE path = ?`, filePath).Scan(&etag, &lastModified)
	if err == sql.ErrNoRows {
		vlog("metadata not found for %s", filePath)
		return "", "", nil // No metadata stored, not an error
	}
	if err == nil {
		vlog("metadata loaded for %s: etag=%q last_modified=%q", filePath, etag, lastModified)
	}
	return etag, lastModified, err
}

func main() {
	configPath := flag.String("config", "remirror.hcl", "Path to config file")
	version := flag.Bool("version", false, "Print version and exit")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose logging")
	flag.Parse()
	verbose = *verboseFlag

	if *version {
		fmt.Println("remirror", VERSION)
		os.Exit(0)
	}
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

	// Initialize metadata database for ETag storage
	if err := init_metadata_db(config.Data); err != nil {
		log.Fatalf("Failed to initialize metadata database: %v", err)
	}
	defer metaDB.Close()
	vlog("metadata database initialized in %s", config.Data)

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

func write_resp_headers(w http.ResponseWriter, resp *http.Response) {

	for k, vs := range resp.Header {
		if k == "Accept-Ranges" {
			continue
		}
		for _, v := range vs {
			//fmt.Printf("proxy back header %#v\t%#v\n", k, v)
			w.Header().Add(k, v)
		}
	}

	w.Header().Set("Server", "remirror")
	w.WriteHeader(resp.StatusCode)
}

// return a download in progress started by another request
func tmp_download(local_path string, w http.ResponseWriter, download *Download, tmp io.ReadCloser) error {
	defer tmp.Close()

	write_resp_headers(w, download.resp)

	written := int64(0)
	done := false
	last := time.Now()

	for {
		n, err := io.Copy(w, tmp)

		if n < 0 {
			panic(fmt.Sprintf("io.Copy returned n %d: Not what I expected!", n))
		}

		written += n

		if err != nil && err != io.EOF {
			log.Printf(`Error while reading concurrent download %s from %s: %v
`,
				local_path, download.tmp_path, err)
			// Not an HTTP error: just return, and the client will hopefully
			// handle a short read correctly.
			return nil
		}

		if n > 0 {
			// cool, try another copy. hopefully the file
			// has more bytes now
			last = time.Now()
			continue
		}

		if done {
			return nil
		}

		// sleep for a bit so the other download has a chance to write
		// more bytes.
		select {
		case <-time.After(time.Second):
			// 60 second timeout for the other goroutine to at least write _something_
			if time.Since(last) > time.Minute {
				log.Printf("Timeout while reading concurrent download %s from %s\n",
					local_path,
					download.tmp_path)
				// Not an HTTP error: just return, and the client will hopefully
				// handle a short read correctly.
				return nil
			}
			continue
		case <-download.tmp_done:
			done = true
			continue
		}
	}
}
