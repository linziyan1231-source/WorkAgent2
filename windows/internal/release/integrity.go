package release

import "sync/atomic"

// integrityVerification gates the per-file SHA-256 comparison in the exported
// VerifyCurrent/VerifyReleasePath runtime checks. It defaults to off for
// controlled intranet deployments, where pointer/manifest parsing, structural,
// and size checks still run but file contents are not rehashed on every start.
// Enable it through the verify_release_integrity configuration before exposing
// a deployment to untrusted networks. Install, activation, and rollback paths
// always hash file contents regardless of this switch.
var integrityVerification atomic.Bool

// SetIntegrityVerification enables or disables per-file SHA-256 comparison in
// the runtime release verification checks. It is process-wide and should be
// set once during startup from the verify_release_integrity configuration.
func SetIntegrityVerification(enabled bool) {
	integrityVerification.Store(enabled)
}
