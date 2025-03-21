package plugin

import (
	"errors"
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
	ProcessRequest(r *http.Request) (ProcessResult, error)

	// ProcessResponse is called after receiving the response.
	// It can modify the response or cancel it by returning an error.
	ProcessResponse(r *http.Response) (ProcessResult, error)
}

// ArmorPluginManager maintains a list of plugins and calls them.
type ArmorPluginManager struct {
	plugins []ArmorPlugin
}

// NewArmorPluginManager creates an empty plugin manager.
func NewArmorPluginManager() *ArmorPluginManager {
	return &ArmorPluginManager{
		plugins: []ArmorPlugin{},
	}
}

// Register adds a new plugin to the manager.
func (apm *ArmorPluginManager) Register(ap ArmorPlugin) {
	apm.plugins = append(apm.plugins, ap)
}

// ProcessRequest iterates through all registered plugins and calls
// their ProcessRequest method. If any plugin returns Cancel, the
// request is cancelled and the error is returned.
func (apm *ArmorPluginManager) ProcessRequest(r *http.Request) (string, ProcessResult, error) {
	for _, plugin := range apm.plugins {

		outcome, err := plugin.ProcessRequest(r)

		if err != nil {
			return plugin.Name(), Cancel, fmt.Errorf("plugin %s encountered an error: %w", plugin.Name(), err)
		}
		if outcome == Cancel {
			return plugin.Name(), Cancel, nil
		}
	}
	return "", Continue, nil
}

// ProcessResponse iterates through all registered plugins and calls
// their ProcessResponse method. If any plugin returns Cancel, the
// response is cancelled and the error is returned.
func (apm *ArmorPluginManager) ProcessResponse(r *http.Response) error {
	for _, plugin := range apm.plugins {
		outcome, err := plugin.ProcessResponse(r)
		if err != nil {
			return fmt.Errorf("plugin %s encountered an error: %w", plugin.Name(), err)
		}
		if outcome == Cancel {
			return fmt.Errorf("plugin %s cancelled the response", plugin.Name())
		}
	}
	return nil
}

// ArmorPluginFactory is responsible for creating new plugin instances.
type ArmorPluginFactory struct{}

// NewArmorPluginFactory creates a new PluginFactory.
func NewArmorPluginFactory() *ArmorPluginFactory {
	return &ArmorPluginFactory{}
}

// CreateArmorPlugin takes a plugin name and configuration parameters,
// and returns an instance of the corresponding plugin.
func (apf *ArmorPluginFactory) CreatePlugin(name string, config map[string]any) (ArmorPlugin, error) {
	switch name {

	case "blocklist":
		// Look for the blocklist configuration in the passed map
		value, ok := config["blocklist"]
		if !ok {
			return nil, errors.New("missing blocklist configuration in the passed config map")
		}
		// Make sure the value is a map[string]bool
		blockedHosts, ok := value.(map[string]bool)
		if !ok {
			return nil, errors.New("blocklist configuration must be map[string]bool")
		}
		return NewBlocklistPlugin(blockedHosts), nil

	case "block_methods":
		// Look for the block_methods configuration in the passed map
		value, ok := config["block_methods"]
		if !ok {
			return nil, errors.New("missing block_methods configuration in the passed config map")
		}
		// Make sure the value is a map[string]bool
		blockedMethods, ok := value.(map[string]bool)
		if !ok {
			return nil, errors.New("block_methods configuration must be map[string]bool")
		}
		return NewBlockMethodsPlugin(blockedMethods), nil

	default:
		return nil, fmt.Errorf("unknown plugin name: %s", name)
	}
}
