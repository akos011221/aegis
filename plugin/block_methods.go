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

// ProcessRequest checks if the request method is blocked.
func (bpm *BlockMethodsPlugin) ProcessRequest(r *http.Request) (ProcessResult, error) {
	if _, ok := bpm.methods[r.Method]; ok {
		return Cancel, nil
	}
	return Continue, nil
}

// ProcessResponse does nothing, let's the response pass.
func (bpm *BlockMethodsPlugin) ProcessResponse(r *http.Response) (ProcessResult, error) {
	return Continue, nil
}
