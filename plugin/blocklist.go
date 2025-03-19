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

// NewBlocklistPlugin creates a BlocklistPlugin with the provided list.
func NewBlocklistPlugin(blocklist map[string]bool) *BlocklistPlugin {
	return &BlocklistPlugin{blocklist: blocklist}
}

// Name returns the plugin's name.
func (bp *BlocklistPlugin) Name() string {
	return "blocklist"
}

// ProcessRequest checks if the request URL constains a blocked host.
func (bp *BlocklistPlugin) ProcessRequest(r *http.Request) (ProcessResult, error) {
	// Since the plugin has to check the host, it has to remove the port from req.Host
	host := strings.TrimSpace(helpers.HostWithoutPort(r.Host))

	if _, ok := bp.blocklist[host]; ok {
		return Cancel, nil
	}
	return Continue, nil
}

// ProcessResponse does nothing, let's the response pass.
func (bp *BlocklistPlugin) ProcessResponse(r *http.Response) (ProcessResult, error) {
	return Continue, nil
}
