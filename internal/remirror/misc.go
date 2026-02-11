package remirror

import (
	"fmt"
	"net/http"
)

// Hop-by-hop headers. These are removed when sent upstream.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = map[string]bool{
	"Connection":          true,
	"Proxy-Connection":    true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

type HTTPError int

func (e HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d %s", e, http.StatusText(e.Code()))
}
func (e HTTPError) Code() int {
	return int(e)
}
