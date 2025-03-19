package plugin

import "net/http"

type Plugin interface {
	// Process processes the plugin for the request
	Process(req *http.Request) error

	// Name returns the name of the plugin
	Name() string

	// ActionMessage returns the general action description of the plugin
	ActionDescription() string
}
