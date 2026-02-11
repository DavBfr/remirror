package remirror

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
)

type Match struct {
	Pattern string `hcl:"pattern"`
	Action  string `hcl:"action"`
	Rewrite bool   `hcl:"rewrite"`
}

type compiledMatch struct {
	regex   *regexp.Regexp
	action  string
	rewrite bool
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

func handle_client_conditionals(w http.ResponseWriter, r *http.Request, request_path string, fileInfo os.FileInfo) bool {
	etag, lastModified, _, metaErr := get_metadata(request_path)
	if metaErr != nil {
		vlog("conditional metadata lookup failed for %s: %v", request_path, metaErr)
	}
	if lastModified == "" {
		lastModified = fileInfo.ModTime().UTC().Format(http.TimeFormat)
	}

	if inm := r.Header.Get("If-None-Match"); inm != "" && etag != "" {
		if etag_matches(inm, etag) {
			vlog("conditional If-None-Match hit for %s", request_path)
			touch_metadata(request_path)
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
				vlog("conditional If-Modified-Since hit for %s", request_path)
				touch_metadata(request_path)
				set_cache_metadata_headers(w, etag, lastModified)
				w.Header().Set("Server", "remirror")
				w.WriteHeader(http.StatusNotModified)
				return true
			}
		}
	}

	return false
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
			regex:   re,
			action:  action,
			rewrite: m.Rewrite,
		})
	}
	return nil
}
