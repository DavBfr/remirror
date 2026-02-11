package remirror

import (
	"log"
	"net/http"
	"strings"
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
