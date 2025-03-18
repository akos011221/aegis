package filter

import (
	"net"
	"net/http"
	"time"
)

const (
	ArmorBlockedMessage = "This site is blocked by Armor."

	CategorySocialMedia    byte = 1 << 0
	CategoryAlcoholTobacco byte = 1 << 1
	CategoryDating         byte = 1 << 2
	CategoryJobSearch      byte = 1 << 3
)

// Filters contains the filters that can be applied by Armor.
type FilterConfig struct {
	Blocklist        map[string]any
	SiteWithCategory map[string]byte
}

func DefaultFilters() FilterConfig {
	return FilterConfig{
		Blocklist: map[string]any{
			"facebook.com": struct{}{},
		},
		SiteWithCategory: map[string]byte{
			"instagram.com": CategorySocialMedia,
			"tinder.com":    CategoryDating,
			"linkedin.com":  CategoryJobSearch,
		},
	}
}

// ApplyFilter checks if the request should be blocked based on the host.
func ApplyFilter(f FilterConfig, w http.ResponseWriter, r *http.Request) bool {
	// Get the current hour for time-based filtering
	now := time.Now().Hour()

	// Remove the port from the request host
	var hostWithoutPort string
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		hostWithoutPort = h
	}

	// General blocklist for sites
	if _, ok := f.Blocklist[hostWithoutPort]; ok {
		http.Error(w, ArmorBlockedMessage, http.StatusForbidden)
		return true
	}

	// Category-based filtering
	if f.SiteWithCategory[hostWithoutPort]&CategorySocialMedia != 0 && now >= 8 && now <= 17 {
		http.Error(w, ArmorBlockedMessage, http.StatusForbidden)
		return true
	}
	if f.SiteWithCategory[hostWithoutPort]&CategoryJobSearch != 0 {
		http.Error(w, ArmorBlockedMessage, http.StatusForbidden)
		return true
	}
	if f.SiteWithCategory[hostWithoutPort]&CategoryDating != 0 && now >= 8 && now <= 17 {
		http.Error(w, ArmorBlockedMessage, http.StatusForbidden)
		return true
	}

	return false
}
