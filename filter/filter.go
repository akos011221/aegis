package filter

import "net/http"

// Blocklist contains domain to block (e.g., ad servers).
var Blocklist = map[string]bool{
	"tbd": true,
}

// ApplyFilter checks if the request should be blocked based on the host.
func ApplyFilter(w http.ResponseWriter, r *http.Request) bool {
	if Blocklist[r.Host] {
		http.Error(w, "Request blocked by Aegis", http.StatusForbidden)
		return true
	}
	return false
}
