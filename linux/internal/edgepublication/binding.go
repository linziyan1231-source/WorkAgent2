package edgepublication

import (
	"errors"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

const (
	productionPortalAddress      = "127.0.0.1:42580"
	productionPortalPublicOrigin = "https://workagent.example.invalid"
)

// ValidateProductionPortalEdgeBinding proves the Portal listener and public
// origin still match the signed Caddy publication boundary.
func ValidateProductionPortalEdgeBinding(portal config.Portal) error {
	if portal.Listener.Address != productionPortalAddress || portal.Listener.PublicOrigin != productionPortalPublicOrigin {
		return errors.New("Portal listener and public origin do not match the signed Caddy publication boundary")
	}
	return nil
}
