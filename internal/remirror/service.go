package remirror

import (
	"compress/gzip"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/hcl"
	_ "modernc.org/sqlite"
)

// Headers to exclude when making upstream requests (in addition to hop-by-hop headers)
var excludeHeadersUpstream = map[string]bool{
	"Range": true, // Always request full file from upstream, handle ranges locally
}

var (
	http_client = http.Client{}
	metaDB      *sql.DB
	metaDB_mu   sync.Mutex // Protects database write operations
	verbose     bool
	cacheRoot   string

	downloads_mu sync.Mutex
	downloads    = map[string]*Download{}
)

type Download struct {
	resp *http.Response

	tmp_path string
	tmp_done chan struct{} // will be closed when download is done and final bytes written
}

func set_cache_metadata_headers(w http.ResponseWriter, etag, lastModified string) {
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	if lastModified != "" {
		w.Header().Set("Last-Modified", lastModified)
	}
	// Always advertise that we support range requests
	w.Header().Set("Accept-Ranges", "bytes")
}

// shouldExcludeHeader checks if a header should be excluded when proxying upstream
func shouldExcludeHeader(k string) bool {
	return hopHeaders[k] || excludeHeadersUpstream[k]
}

// decompressResponseBody returns a reader that decompresses the response body if needed
// based on the Content-Encoding header, and removes the Content-Encoding header
func decompressResponseBody(resp *http.Response) (io.ReadCloser, error) {
	encoding := resp.Header.Get("Content-Encoding")
	if encoding == "" {
		return resp.Body, nil
	}

	vlog("decompressing response with Content-Encoding: %s", encoding)

	switch encoding {
	case "gzip":
		gr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		// Remove the Content-Encoding header since we're decompressing
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length") // Length will change after decompression
		resp.ContentLength = -1           // Mark as unknown since decompressed size differs
		return gr, nil
	case "deflate", "compress", "br":
		// For now, log and pass through. Go's net/http doesn't support these natively
		// Clients should send Accept-Encoding to get gzip instead
		vlog("unsupported Content-Encoding: %s, passing through", encoding)
		return resp.Body, nil
	default:
		// Unknown encoding, pass through
		return resp.Body, nil
	}
}

func serve_cached(w http.ResponseWriter, r *http.Request, request_path, storage_path string, fileInfo os.FileInfo) {
	if handle_client_conditionals(w, r, request_path, fileInfo) {
		return
	}
	touch_metadata(request_path)
	etag, lastModified, _, _ := get_metadata(request_path)
	if lastModified == "" {
		lastModified = fileInfo.ModTime().UTC().Format(http.TimeFormat)
	}
	set_cache_metadata_headers(w, etag, lastModified)

	// Open file and serve it (handles Range requests automatically)
	file, err := os.Open(storage_path)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer file.Close()

	// Use http.ServeContent which handles Range requests, If-Range, etc.
	http.ServeContent(w, r, path.Base(storage_path), fileInfo.ModTime(), file)
}

// serve_cached_with_rewrite serves cached content with URL rewriting if needed
func serve_cached_with_rewrite(w http.ResponseWriter, r *http.Request, request_path, storage_path string, fileInfo os.FileInfo, shouldRewrite bool, upstreamURL, replacementURL string) {
	if !shouldRewrite {
		serve_cached(w, r, request_path, storage_path, fileInfo)
		return
	}

	if handle_client_conditionals(w, r, request_path, fileInfo) {
		return
	}
	touch_metadata(request_path)
	etag, lastModified, _, _ := get_metadata(request_path)
	if lastModified == "" {
		lastModified = fileInfo.ModTime().UTC().Format(http.TimeFormat)
	}
	set_cache_metadata_headers(w, etag, lastModified)

	// Read file, rewrite, and serve
	content, err := os.ReadFile(storage_path)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	rewritten := rewriteContent(content, upstreamURL, replacementURL)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
	w.Write(rewritten)
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
		if !shouldExcludeHeader(k) {
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
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(resp.StatusCode)

	// Decompress response body if needed
	decompressed, err := decompressResponseBody(resp)
	if err != nil {
		return err
	}
	defer decompressed.Close()

	// Stream response body
	_, err = io.Copy(w, decompressed)
	return err
}

// rewriteContent replaces upstream URLs with local mirror URLs in the content
func rewriteContent(content []byte, upstreamURL, replacementURL string) []byte {
	// Parse the upstream URL to get the base (without path)
	if u, err := url.Parse(upstreamURL); err == nil {
		upstreamBase := u.Scheme + "://" + u.Host
		if u.Path != "" && u.Path != "/" {
			upstreamBase += u.Path
		}
		// Remove trailing slash for consistent matching
		upstreamBase = strings.TrimSuffix(upstreamBase, "/")
		replacementURL = strings.TrimSuffix(replacementURL, "/")

		vlog("rewriting %s -> %s", upstreamBase, replacementURL)
		return []byte(strings.ReplaceAll(string(content), upstreamBase, replacementURL))
	}
	return content
}

func load_configs(config *Config, configPath string) error {
	log.Printf("Loading configuration from %#v ...\n", configPath)
	configBytes, err := os.ReadFile(configPath)
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
func revalidate_cache(w http.ResponseWriter, r *http.Request, request_path, storage_path string, fileInfo os.FileInfo, remote_url string, shouldRewrite bool, upstreamBase, replacementURL string) bool {
	// Don't revalidate on Range requests
	if r.Header.Get("Range") != "" {
		// For range requests on cached files, serve directly with cache metadata
		touch_metadata(request_path)
		etag, lastModified, _, _ := get_metadata(request_path)
		if lastModified == "" {
			lastModified = fileInfo.ModTime().UTC().Format(http.TimeFormat)
		}
		set_cache_metadata_headers(w, etag, lastModified)

		// Open file and serve it with Range support
		file, err := os.Open(storage_path)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return true
		}
		defer file.Close()
		http.ServeContent(w, r, path.Base(storage_path), fileInfo.ModTime(), file)
		return true
	}

	req, err := http.NewRequest("GET", remote_url, nil)
	if err != nil {
		// If we can't create the request, serve from cache
		log.Printf("Error creating revalidation request, serving from cache: %v", err)
		serve_cached_with_rewrite(w, r, request_path, storage_path, fileInfo, shouldRewrite, upstreamBase, replacementURL)
		return true
	}

	// Try to use ETag and Last-Modified if we have them stored
	etag, lastModified, _, metaErr := get_metadata(request_path)
	if metaErr == nil && etag != "" {
		req.Header.Set("If-None-Match", etag)
		vlog("revalidate ETag for %s: %s", request_path, etag)
	} else if metaErr != nil {
		vlog("revalidate metadata lookup failed for %s: %v", request_path, metaErr)
	} else {
		vlog("no stored ETag for %s", request_path)
	}

	// Add If-Modified-Since header as fallback
	ims := lastModified
	if ims == "" {
		ims = fileInfo.ModTime().UTC().Format(http.TimeFormat)
	}
	req.Header.Set("If-Modified-Since", ims)
	vlog("revalidate If-Modified-Since for %s: %s", request_path, ims)
	vlog_headers("revalidate request", req.Header)

	// Copy original request headers (excluding Range for revalidation)
	for k, vs := range r.Header {
		if !shouldExcludeHeader(k) {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
	}

	resp, err := http_client.Do(req)
	if err != nil {
		// Network error, serve from cache
		log.Printf("Remote unreachable during revalidation, serving from cache: %v", err)
		serve_cached_with_rewrite(w, r, request_path, storage_path, fileInfo, shouldRewrite, upstreamBase, replacementURL)
		return true
	}
	defer resp.Body.Close()
	vlog("revalidate response %d for %s", resp.StatusCode, remote_url)
	vlog_headers("revalidate response", resp.Header)

	if resp.StatusCode == 304 {
		// Not modified, serve from cache
		log.Printf("Cache hit (304): %s", request_path)
		serve_cached_with_rewrite(w, r, request_path, storage_path, fileInfo, shouldRewrite, upstreamBase, replacementURL)
		return true
	}

	if resp.StatusCode == 200 {
		// File was modified, we need to update it
		// Return false so the main handler downloads it
		log.Printf("Cache stale (200): %s", request_path)
		return false
	}

	if resp.StatusCode >= 500 {
		// Server error, serve from cache
		log.Printf("Remote error %d during revalidation, serving from cache", resp.StatusCode)
		serve_cached_with_rewrite(w, r, request_path, storage_path, fileInfo, shouldRewrite, upstreamBase, replacementURL)
		return true
	}

	if resp.StatusCode == 404 {
		// File no longer exists upstream, but we have it cached
		// Serve from cache anyway
		log.Printf("File not found upstream (404), serving from cache: %s", request_path)
		serve_cached_with_rewrite(w, r, request_path, storage_path, fileInfo, shouldRewrite, upstreamBase, replacementURL)
		return true
	}

	// For other status codes, serve from cache
	log.Printf("Unexpected status %d during revalidation, serving from cache", resp.StatusCode)
	serve_cached_with_rewrite(w, r, request_path, storage_path, fileInfo, shouldRewrite, upstreamBase, replacementURL)
	return true
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
	w.Header().Set("Accept-Ranges", "bytes")
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
