package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/hcl"
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

	// If nil, default match set will be used
	Matches []Match
}
type Match struct {
	Prefix string
	Suffix string
	Skip   bool // skip = true means this is a "don't match" rule
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
		ss := m.Prefix + "*" + m.Suffix
		if m.Skip {
			ss += " skip"
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

	downloads_mu sync.Mutex
	downloads    = map[string]*Download{}
)

type Download struct {
	resp *http.Response

	tmp_path string
	tmp_done chan struct{} // will be closed when download is done and final bytes written
}

func (mirror Mirror) should_cache(path string) bool {
	// Special rules for Debian/Ubuntu
	if strings.HasSuffix(path, "/Packages.gz") || strings.HasSuffix(path, "/Sources.gz") {
		return false
	}

	// Special rules for Arch
	if strings.HasSuffix(path, ".abs.tar.gz") ||
		strings.HasSuffix(path, ".db.tar.gz") ||
		strings.HasSuffix(path, ".files.tar.gz") ||
		strings.HasSuffix(path, ".links.tar.gz") {
		return false
	}

	// Use custom match rules?
	if len(mirror.Matches) > 0 {
		for _, m := range mirror.Matches {
			if strings.HasPrefix(path, m.Prefix) &&
				strings.HasSuffix(path, m.Suffix) {
				return !m.Skip
			}
		}
		return false
	}

	// Otherwise cache everything that looks like an archive.
	if strings.HasSuffix(path, ".xz") ||
		strings.HasSuffix(path, ".gz") ||
		strings.HasSuffix(path, ".bz2") ||
		strings.HasSuffix(path, ".zip") ||
		strings.HasSuffix(path, ".tgz") ||
		strings.HasSuffix(path, ".rpm") ||
		strings.HasSuffix(path, "-rpm.bin") ||
		strings.HasSuffix(path, ".deb") ||
		strings.HasSuffix(path, ".jar") ||
		strings.HasSuffix(path, ".xz.sig") {
		return true
	}
	return false
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

				if mirror.should_cache(remote_url) {
					local_path = config.Data + path.Clean(r.URL.Path)

					_, err := os.Stat(local_path)
					if err == nil {
						fileserver.ServeHTTP(w, r)
						return nil
					}
				}

				var download *Download
				var ok bool

				downloads_mu.Lock()

				if r.Header.Get("Range") == "" && local_path != "" {
					download, ok = downloads[local_path]
					if ok {
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
					return err
				}

				for k, vs := range r.Header {
					if !hopHeaders[k] {
						for _, v := range vs {
							req.Header.Add(k, v)
						}
					}
				}

				resp, err := http_client.Do(req)
				if err != nil {
					downloads_mu.Unlock()
					return err
				}
				defer resp.Body.Close()

				// Try another mirror if we get certain status codes
				if resp.StatusCode == 404 ||
					resp.StatusCode == 500 ||
					resp.StatusCode == 503 {
					downloads_mu.Unlock()
					continue
				}

				out := io.Writer(w)

				tmp_path := ""

				var tmp_needs_final_close io.Closer

				// We don't want to cache the result if the server
				// returns with a 206 Partial Content
				if resp.StatusCode == 200 && local_path != "" {
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
				applied = true
				break
			}
		}
		if !applied {
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
		if len(parts) < 2 || len(parts) > 3 {
			return nil, fmt.Errorf("Invalid match entry %q (expected prefix:suffix[:skip])", entry)
		}
		m := Match{
			Prefix: parts[0],
			Suffix: parts[1],
		}
		if len(parts) == 3 {
			b, err := strconv.ParseBool(parts[2])
			if err != nil {
				return nil, fmt.Errorf("Invalid match skip value %q in %q", parts[2], entry)
			}
			m.Skip = b
		}
		matches = append(matches, m)
	}
	return matches, nil
}

func main() {
	configPath := flag.String("config", "remirror.hcl", "Path to config file")
	version := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

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
			log.Printf("Error while reading concurrent download %#s from %#s: %v\n",
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
				log.Println("Timeout while reading concurrent download %#s from %#s\n",
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
