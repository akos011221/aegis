package filter

import "net/http"

// Filters contains the filters that can be applied by Armor.
type FilterConfig struct {
	Blocklist map[string]any
}

func DefaultFilters() FilterConfig {
	return FilterConfig{
		Blocklist: map[string]any{
			"facebook.com": struct{}{},
		},
	}
}

// ApplyFilter checks if the request should be blocked based on the host.
func ApplyFilter(f FilterConfig, w http.ResponseWriter, r *http.Request) bool {
	if _, ok := f.Blocklist[r.Host]; ok {
		http.Error(w, "Request blocked by Armor", http.StatusForbidden)
		return true
	}
	return false
}
