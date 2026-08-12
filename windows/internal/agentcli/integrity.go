package agentcli

import "sync/atomic"

// VerifyIntegrityEnvironment is read by the standalone AionAgentCli binary,
// which does not load Portal configuration: "1" enables per-file SHA-256
// verification, anything else keeps the default off. UserHost propagates it
// to agent CLI launcher processes from its verify_release_integrity setting.
const VerifyIntegrityEnvironment = "AIONUI_VERIFY_RELEASE_INTEGRITY"

// integrityVerification gates the per-file SHA-256 comparison in the exported
// VerifyCurrent/VerifyRelease runtime checks. It defaults to off for
// controlled intranet deployments, where pointer/manifest parsing, structural,
// and size checks still run but file contents are not rehashed on every start.
// Enable it through the verify_release_integrity configuration (or the
// VerifyIntegrityEnvironment variable for the standalone binary) before
// exposing a deployment to untrusted networks. Activation always hashes file
// contents regardless of this switch.
var integrityVerification atomic.Bool

// SetIntegrityVerification enables or disables per-file SHA-256 comparison in
// the runtime agent CLI release verification checks. It is process-wide and
// should be set once during startup.
func SetIntegrityVerification(enabled bool) {
	integrityVerification.Store(enabled)
}
