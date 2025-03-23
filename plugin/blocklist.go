package plugin

import (
	"net/http"
	"strings"

	"github.com/akos011221/armor/helpers"
)

// BlocklistPlugin holds a slice if blocked hosts.
type BlocklistPlugin struct {
	blocklist map[string]bool
}

// NewBlocklistPlugin creates a BlocklistPlugin with the provided map.
func NewBlocklistPlugin(blocklist map[string]bool) *BlocklistPlugin {
	return &BlocklistPlugin{blocklist: blocklist}
}

// Name returns the plugin's name.
func (bp *BlocklistPlugin) Name() string {
	return "blocklist"
}

// ProcessConnectRequest checks if the request URL constains a blocked host.
func (bp *BlocklistPlugin) ProcessConnectReq(r *http.Request) (int, error) {
	// Since the plugin has to check the host, it has to remove the port from req.Host
	host := strings.TrimSpace(helpers.HostWithoutPort(r.Host))

	if _, ok := bp.blocklist[host]; ok {
		return http.StatusForbidden, nil
	}
	return http.StatusOK, nil
}

// ProcessMitmReq does nothing, the plugin is only interested in the CONNECT request.
func (bp *BlocklistPlugin) ProcessMitmReq(r *http.Request) (int, error) {
	return http.StatusOK, nil
}
