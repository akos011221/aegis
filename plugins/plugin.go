package plugins

import (
	"fmt"
	"net/http"
)

// ProcessResult is an alias for int, used it to represent
// the outcome of processing a request or response by a plugin.
type ProcessResult int

// Possible values for ProcessResult type.
// Using iota to automatically assign values to the constants.
const (
	Continue ProcessResult = iota
	Cancel
)

// Plugin is the interface that every Armor Plugin must implement.
type ArmorPlugin interface {
	// Name returns the plugin's name.
	Name() string

	// ProcessRequest is called before forwading the request.
	// It can modify the request or cancel it by returning an error.
	ProcessRequest(req *http.Request) (ProcessResult, error)

	// ProcessResponse is called after receiving the response.
	// It can modify the response or cancel it by returning an error.
	ProcessResponse(resp *http.Response) (ProcessResult, error)
}

// PluginManager maintains a list of plugins and calls them.
type PluginManager struct {
	plugins []ArmorPlugin
}

// NewPluginManager creates an empty plugin manager.
func NewPluginManager() *PluginManager {
	return &PluginManager{
		plugins: []ArmorPlugin{},
	}
}

// Register adds a new plugin to the manager.
func (pm *PluginManager) Register(ap ArmorPlugin) {
	pm.plugins = append(pm.plugins, ap)
}

// ProcessRequest iterates through all registered plugins and calls
// their ProcessRequest method. If any plugin returns Cancel, the
// request is cancelled and the error is returned.
func (pm *PluginManager) ProcessRequest(req *http.Request) error {
	for _, plugin := range pm.plugins {
		outcome, err := plugin.ProcessRequest(req)
		if err != nil {
			return fmt.Errorf("plugin %s encountered an error: %w", plugin.Name(), err)
		}
		if outcome == Cancel {
			return fmt.Errorf("plugin %s cancelled the request", plugin.Name())
		}
	}
	return nil
}

// ProcessResponse iterates through all registered plugins and calls
// their ProcessResponse method. If any plugin returns Cancel, the
// response is cancelled and the error is returned.
func (pm *PluginManager) ProcessResponse(resp *http.Response) error {
	for _, plugin := range pm.plugins {
		outcome, err := plugin.ProcessResponse(resp)
		if err != nil {
			return fmt.Errorf("plugin %s encountered an error: %w", plugin.Name(), err)
		}
		if outcome == Cancel {
			return fmt.Errorf("plugin %s cancelled the response", plugin.Name())
		}
	}
	return nil
}
