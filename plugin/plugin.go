package plugin

import (
	"errors"
	"fmt"
	"net/http"
)

// Plugin is the interface that every Armor Plugin must implement.
type ArmorPlugin interface {
	// Name returns the plugin's name.
	Name() string

	// ProcessRequest is called before forwading the request.
	// It can modify the request or terminate it.
	ProcessRequest(r *http.Request) (int, error)

	// ProcessResponse is called after receiving the response.
	// It can modify the response or terminate it.
	ProcessResponse(r *http.Response) (int, error)
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
// their ProcessRequest method. If any plugin returns 4xx, the
// request is terminated and the error is returned.
func (apm *ArmorPluginManager) ProcessRequest(r *http.Request) (string, int, error) {
	for _, plugin := range apm.plugins {

		status, err := plugin.ProcessRequest(r)

		if err != nil {
			return plugin.Name(), http.StatusServiceUnavailable, fmt.Errorf("plugin %s encountered an error: %w", plugin.Name(), err)
		}
		if status >= 400 && status < 500 {
			return plugin.Name(), int(status), nil
		}
	}
	return "", http.StatusOK, nil
}

// ProcessResponse iterates through all registered plugins and calls
// their ProcessResponse method. If any plugin returns 4xx, the
// response is terminated and the error is returned.
func (apm *ArmorPluginManager) ProcessResponse(r *http.Response) error {
	for _, plugin := range apm.plugins {
		status, err := plugin.ProcessResponse(r)
		if err != nil {
			return fmt.Errorf("plugin %s encountered an error: %w", plugin.Name(), err)
		}
		if status >= 400 && status < 500 {
			return err
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
