package plugin

import "net/http"

// BlockMethodPlugin holds a slice if blocked HTTP methods.
type BlockMethodsPlugin struct {
	methods map[string]bool
}

// NewBlockMethodsPlugin creates a BlocklistPlugin with the provided map.
func NewBlockMethodsPlugin(methods map[string]bool) *BlockMethodsPlugin {
	return &BlockMethodsPlugin{methods: methods}
}

// Name returns the plugin's name.
func (bmp *BlockMethodsPlugin) Name() string {
	return "block_methods"
}

// ProcessConnectRequest does nothing, the plugin is only interested in the actual client to server requests.
func (bpm *BlockMethodsPlugin) ProcessConnectReq(r *http.Request) (int, error) {
	return http.StatusOK, nil
}

// ProcessMitmReq checks if the request method is blocked.
func (bpm *BlockMethodsPlugin) ProcessMitmReq(r *http.Request) (int, error) {
	if _, ok := bpm.methods[r.Method]; ok {
		return http.StatusMethodNotAllowed, nil
	}
	return http.StatusOK, nil
}
