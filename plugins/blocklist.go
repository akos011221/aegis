package plugins

import (
	"bufio"
	"fmt"
	"net/http"
	"os"

	"github.com/akos011221/armor/helpers"
)

type Blocklist struct {
	Blocklist map[string]struct{}
}

// NewBlocklist creates a new Blocklist from the given file.
func NewBlocklist(f *os.File) *Blocklist {
	b := &Blocklist{
		Blocklist: make(map[string]struct{}),
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		b.Blocklist[scanner.Text()] = struct{}{}
	}

	return b
}

// Process processes the Blocklist plugin for the given request.
func (b *Blocklist) Process(w http.ResponseWriter, r *http.Request) {
	hostWithoutPort := helpers.HostWithoutPort(r.Host)

	if _, ok := b.Blocklist[hostWithoutPort]; ok {
		http.Error(w, fmt.Sprintf("%s by %s plugin", b.ActionDescription(), b.Name()), http.StatusForbidden)
		return
	}
}

func (b *Blocklist) Name() string {
	return "Blocklist"
}

func (b *Blocklist) ActionDescription() string {
	return "Access denied"
}
