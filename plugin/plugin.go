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

	// ProcessConnectReq is called when the proxy receives a CONNECT request.
	ProcessInitReq(r *http.Request) (int, error)

	// ProcessMitmReq is called on the MITM connection.
	ProcessMitmReq(r *http.Request) (int, error)
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

// ProcessConnectReq processes the `CONNECT` requests.
// It iterates through all registered plugins and calls their
// ProcessConnectReq method. If any plugin returns 4xx, the
// name of that plugin is returned along with the status code.
func (apm *ArmorPluginManager) ProcessInitReq(r *http.Request) (string, int, error) {
	for _, plugin := range apm.plugins {

		status, err := plugin.ProcessInitReq(r)

		if err != nil {
			return plugin.Name(), http.StatusServiceUnavailable, fmt.Errorf("plugin %s encountered an error: %w", plugin.Name(), err)
		}
		if status >= 400 && status < 500 {
			return plugin.Name(), int(status), nil
		}
	}
	return "", http.StatusOK, nil
}

func (apm *ArmorPluginManager) ProcessMitmReq(r *http.Request) (string, int, error) {
	for _, plugin := range apm.plugins {

		status, err := plugin.ProcessMitmReq(r)

		if err != nil {
			return plugin.Name(), http.StatusServiceUnavailable, fmt.Errorf("plugin %s encountered an error: %w", plugin.Name(), err)
		}
		if status >= 400 && status < 500 {
			return plugin.Name(), int(status), nil
		}
	}
	return "", http.StatusOK, nil
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
		value, ok := config["blocklist"]
		if !ok {
			return nil, errors.New("missing blocklist configuration in the passed config map")
		}
		blockedHosts, ok := value.(map[string]bool)
		if !ok {
			return nil, errors.New("blocklist configuration must be map[string]bool")
		}
		return NewBlocklistPlugin(blockedHosts), nil

	case "block_methods":
		value, ok := config["block_methods"]
		if !ok {
			return nil, errors.New("missing block_methods configuration in the passed config map")
		}
		blockedMethods, ok := value.(map[string]bool)
		if !ok {
			return nil, errors.New("block_methods configuration must be map[string]bool")
		}
		return NewBlockMethodsPlugin(blockedMethods), nil

	default:
		return nil, fmt.Errorf("unknown plugin name: %s", name)
	}
}
