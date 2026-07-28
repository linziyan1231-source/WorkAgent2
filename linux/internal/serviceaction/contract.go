//go:build linux

package serviceaction

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/fsutil"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
)

const coreChatForwardManagerExec = "/usr/libexec/workagent-fixed-root-exec-v1 chatforward /opt/workagent/shared/chatforward/integration/run-server.sh /run/credentials/workagent-chatforward.service/chatforward-key"

type systemdExecContract struct {
	executable    string
	flattenedArgv string
	privileged    bool
}

func exactSystemdExec(value, executable, flattenedArgv string) bool {
	prefix := "{ path=" + executable + " ; argv[]=" + flattenedArgv + " ; ignore_errors=no ;"
	return strings.HasPrefix(value, prefix) && strings.HasSuffix(value, " }") && strings.Count(value, "{ path=") == 1
}

func exactPrivilegedSystemdExec(value, executable, flattenedArgv string) bool {
	prefix := "{ path=" + executable + " ; argv[]=" + flattenedArgv + " ; flags=privileged ;"
	return strings.HasPrefix(value, prefix) && strings.HasSuffix(value, " }") && strings.Count(value, "{ path=") == 1
}

func exactSystemdExecSequence(value string, contracts ...systemdExecContract) bool {
	if len(contracts) == 0 || strings.Count(value, "{ path=") != len(contracts) {
		return false
	}
	remaining := value
	for index, contract := range contracts {
		end := strings.Index(remaining, " }")
		if end < 0 {
			return false
		}
		record := remaining[:end+2]
		matches := exactSystemdExec(record, contract.executable, contract.flattenedArgv)
		if contract.privileged {
			matches = exactPrivilegedSystemdExec(record, contract.executable, contract.flattenedArgv)
		}
		if !matches {
			return false
		}
		remaining = remaining[end+2:]
		if index+1 < len(contracts) {
			if !strings.HasPrefix(remaining, " ; ") {
				return false
			}
			remaining = remaining[3:]
		}
	}
	return remaining == ""
}

func exactSystemdExtendedExecSequence(value string, contracts ...systemdExecContract) bool {
	if len(contracts) == 0 || strings.Count(value, "{ path=") != len(contracts) {
		return false
	}
	remaining := value
	for index, contract := range contracts {
		end := strings.Index(remaining, " }")
		if end < 0 {
			return false
		}
		record := remaining[:end+2]
		flags := ""
		if contract.privileged {
			flags = "privileged"
		}
		prefix := "{ path=" + contract.executable + " ; argv[]=" + contract.flattenedArgv + " ; flags=" + flags + " ;"
		if !strings.HasPrefix(record, prefix) || !strings.HasSuffix(record, " }") || strings.Count(record, "{ path=") != 1 {
			return false
		}
		remaining = remaining[end+2:]
		if index+1 < len(contracts) {
			if !strings.HasPrefix(remaining, " ; ") {
				return false
			}
			remaining = remaining[3:]
		}
	}
	return remaining == ""
}

func exactCoreManagerExecVector(plainValue, extendedValue string, contracts []systemdExecContract) bool {
	if len(contracts) == 0 {
		return plainValue == "" && extendedValue == ""
	}
	plain := append([]systemdExecContract(nil), contracts...)
	for index := range plain {
		plain[index].privileged = false
	}
	return exactSystemdExecSequence(plainValue, plain...) && exactSystemdExtendedExecSequence(extendedValue, contracts...)
}

func verifyCaddyManagerContract(properties map[string]string) error {
	const start = "/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile"
	const reload = "/usr/bin/caddy reload --config /etc/caddy/Caddyfile --force"
	const coreAdmit = "/usr/libexec/workagent-core-activation-admission-v1"
	const admit = "/usr/libexec/workagent-edge-publication-admission-v1"
	const watch = "/usr/libexec/workagent-edge-publication-admission-v1 --watch $MAINPID"
	contract := func(executable, arguments string, privileged bool) systemdExecContract {
		return systemdExecContract{executable: executable, flattenedArgv: arguments, privileged: privileged}
	}
	if properties["NeedDaemonReload"] != "no" || properties["Type"] != "notify" || properties["User"] != "caddy" || properties["Group"] != "caddy" ||
		properties["RuntimeDirectory"] != "caddy-admin" || properties["RuntimeDirectoryMode"] != "0700" ||
		properties["TimeoutStartUSec"] != "6min" || properties["TimeoutStartFailureMode"] != "kill" || properties["KillMode"] != "control-group" ||
		properties["SendSIGKILL"] != "yes" || properties["FinalKillSignal"] != "9" || properties["Restart"] != "no" ||
		properties["NoNewPrivileges"] != "yes" || properties["AmbientCapabilities"] != "cap_net_bind_service" || properties["CapabilityBoundingSet"] != "cap_net_bind_service" ||
		!exactCoreManagerExecVector(properties["ExecStart"], properties["ExecStartEx"], []systemdExecContract{contract("/usr/bin/caddy", start, false)}) ||
		!exactCoreManagerExecVector(properties["ExecStartPre"], properties["ExecStartPreEx"], []systemdExecContract{
			contract("/usr/libexec/workagent-core-activation-admission-v1", coreAdmit, true),
			contract("/usr/libexec/workagent-edge-publication-admission-v1", admit, true),
		}) ||
		!exactCoreManagerExecVector(properties["ExecStartPost"], properties["ExecStartPostEx"], []systemdExecContract{
			contract("/usr/libexec/workagent-edge-publication-admission-v1", watch, true),
		}) ||
		!exactCoreManagerExecVector(properties["ExecReload"], properties["ExecReloadEx"], []systemdExecContract{contract("/usr/bin/caddy", reload, false)}) ||
		!exactCoreManagerExecVector(properties["ExecStop"], properties["ExecStopEx"], nil) ||
		!exactCoreManagerExecVector(properties["ExecStopPost"], properties["ExecStopPostEx"], nil) {
		return errors.New("Caddy manager-loaded unit does not match the signed production contract")
	}
	return nil
}

func verifyServiceActionManagerContract(unit string, properties map[string]string) error {
	switch unit {
	case "workagent-tenant-config-reconcile.service", "cliproxyapi.service", "workagent-notification.service", "workagent-chatforward.service", "workagent-chatforward-browser.service", "workagent-portal.service", "workagent-backup.service", "workagent-healthcheck.service", "workagent-backup.timer", "workagent-healthcheck.timer", "caddy.service":
	default:
		return errors.New("service-action manager contract unit is not allow-listed")
	}
	if err := VerifyCoreManagerContract(unit, properties); err != nil {
		return fmt.Errorf("service-action manager-loaded unit does not match the complete core contract: %w", err)
	}
	// verifyCoreServiceExecVectors already proves every ordinary command
	// vector and every extended vector except the deliberately empty reload-ex
	// field. Keep this boundary independently exact so a transient manager-only
	// reload command can never be admitted by a post-activation service action.
	if unit != "caddy.service" && strings.HasSuffix(unit, ".service") && properties["ExecReloadEx"] != "" {
		return errors.New("service-action manager-loaded service has an unexpected extended reload command")
	}
	return nil
}

// VerifyCoreManagerContract proves a manager-loaded unit still matches the
// complete signed core contract for its exact unit identity.
func VerifyCoreManagerContract(unit string, properties map[string]string) error {
	if properties["LoadState"] != "loaded" || properties["NeedDaemonReload"] != "no" || properties["FragmentPath"] == "" {
		return errors.New("core manager-loaded unit is unavailable or stale")
	}
	persistent := false
	var executable, arguments, serviceType, runtimeUser, runtimeGroup string
	switch unit {
	case "workagent-tenant-catalog-ready.target":
		return errorUnless(properties["UnitFileState"] == "static", "core readiness target is not static")
	case "workagent-backup.timer":
		persistent = true
		if properties["Unit"] != "workagent-backup.service" || properties["Persistent"] != "yes" {
			return errors.New("backup timer manager contract is invalid")
		}
	case "workagent-healthcheck.timer":
		persistent = true
		if properties["Unit"] != "workagent-healthcheck.service" || properties["Persistent"] != "yes" {
			return errors.New("health timer manager contract is invalid")
		}
	case "caddy.service":
		persistent = true
		if err := verifyCaddyManagerContract(properties); err != nil {
			return err
		}
	case "workagent-tenant-config-reconcile.service":
		executable = "/opt/workagent/control/bin/workagent-admin"
		arguments = "/opt/workagent/control/bin/workagent-admin reconcile-tenant-files --config /etc/workagent/portal.json"
		serviceType, runtimeUser, runtimeGroup = "oneshot", "root", "root"
	case "cliproxyapi.service":
		persistent = true
		executable = "/usr/libexec/workagent-fixed-root-exec-v1"
		arguments = "/usr/libexec/workagent-fixed-root-exec-v1 cliproxyapi /opt/workagent/shared/cliproxyapi/bin/cli-proxy-api --config /var/lib/cliproxyapi/config.yaml"
		serviceType, runtimeUser, runtimeGroup = "exec", "cliproxyapi", "cliproxyapi"
	case "workagent-notification.service":
		persistent = true
		executable = "/usr/libexec/workagent-fixed-root-exec-v1"
		arguments = "/usr/libexec/workagent-fixed-root-exec-v1 notification /opt/workagent/control/bin/workagent-notification"
		serviceType, runtimeUser, runtimeGroup = "simple", "workagent-notification", "workagent-notification"
	case "workagent-chatforward.service":
		persistent = true
		executable = "/usr/libexec/workagent-fixed-root-exec-v1"
		arguments = coreChatForwardManagerExec
		serviceType, runtimeUser, runtimeGroup = "exec", "workagent-chatforward", "workagent-chatforward"
	case "workagent-chatforward-browser.service":
		persistent = true
		executable = "/usr/libexec/workagent-fixed-root-exec-v1"
		arguments = "/usr/libexec/workagent-fixed-root-exec-v1 chatforward-browser /opt/workagent/shared/chatforward/integration/run-browser.sh"
		serviceType, runtimeUser, runtimeGroup = "exec", "workagent-chatforward", "workagent-chatforward"
	case "workagent-portal.service":
		persistent = true
		executable = "/bin/bash"
		arguments = `/bin/bash -c /usr/bin/flock --shared 3 || exit 70; exec "$@" workagent-runtime-start /opt/workagent/control/bin/workagent-portal --config /etc/workagent/portal.json`
		serviceType, runtimeUser, runtimeGroup = "notify", "workagent", "workagent"
	case "workagent-backup.service":
		executable = "/usr/bin/flock"
		arguments = "/usr/bin/flock --exclusive --no-fork /run/workagent/activation.lock /usr/libexec/workagent-fixed-root-exec-v1 backup /opt/workagent/control/bin/workagent-backup create --portal-config /etc/workagent/portal.json --config /etc/workagent/backup.json --quiesce-systemd"
		serviceType, runtimeUser, runtimeGroup = "oneshot", "root", "root"
	case "workagent-healthcheck.service":
		executable = "/usr/libexec/workagent-fixed-root-exec-v1"
		arguments = "/usr/libexec/workagent-fixed-root-exec-v1 healthcheck /opt/workagent/control/bin/workagent-healthcheck /var/lib/node_exporter/textfile_collector/workagent_host.prom"
		serviceType, runtimeUser, runtimeGroup = "oneshot", "root", "root"
	default:
		return errors.New("unit is outside the exact core manager contract")
	}
	if persistent {
		if properties["UnitFileState"] != "enabled" && properties["UnitFileState"] != "disabled" {
			return errors.New("persistent core unit has an invalid unit-file state")
		}
	} else if properties["UnitFileState"] != "static" {
		return errors.New("static core unit has an invalid unit-file state")
	}
	mainVectorExact := true
	if executable != "" {
		mainVectorExact = exactCoreManagerExecVector(properties["ExecStart"], properties["ExecStartEx"], []systemdExecContract{{executable: executable, flattenedArgv: arguments}})
	}
	if executable != "" && (properties["Type"] != serviceType || properties["User"] != runtimeUser || properties["Group"] != runtimeGroup || !mainVectorExact ||
		!verifyCoreServiceExecVectors(unit, properties)) {
		return errors.New("core manager-loaded service identity or command does not match policy")
	}
	return nil
}

func verifyCoreServiceExecVectors(unit string, properties map[string]string) bool {
	const (
		coreAdmit     = "/usr/libexec/workagent-core-activation-admission-v1"
		recoveryAdmit = "/usr/libexec/workagent-recovery-activation-admission-v1"
	)
	contract := func(executable, arguments string, privileged bool) systemdExecContract {
		return systemdExecContract{executable: executable, flattenedArgv: arguments, privileged: privileged}
	}
	core := contract(coreAdmit, coreAdmit, true)
	recovery := contract(recoveryAdmit, recoveryAdmit, true)
	var pre, post, stopPost []systemdExecContract
	switch unit {
	case "workagent-tenant-config-reconcile.service":
		pre = []systemdExecContract{
			core, recovery,
			contract("/usr/bin/flock", "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-release verify --root /opt/workagent/control --public-key /etc/workagent/trust/release-signing.pub --scope portal --required-executable bin/workagent-admin --required-executable bin/workagent-release", true),
		}
	case "cliproxyapi.service":
		pre = []systemdExecContract{
			core, recovery,
			contract("/usr/bin/flock", "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-release verify --root /opt/workagent/control --public-key /etc/workagent/trust/release-signing.pub --scope portal --required-executable bin/workagent-cliproxy --required-executable bin/workagent-release", true),
			contract("/usr/bin/flock", "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-release verify --root /opt/workagent/shared --public-key /etc/workagent/trust/release-signing.pub --scope shared --required-executable cliproxyapi/bin/cli-proxy-api --required-executable cliproxyapi/plugins/cpa-key-policy-v0.4.5.so", true),
			contract("/usr/bin/flock", "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-cliproxy prepare --template /etc/cliproxyapi/config.yaml --output /var/lib/cliproxyapi/config.yaml --credential /run/credentials/cliproxyapi.service/cliproxy-management-key --state-root /var/lib/cliproxyapi", true),
		}
		post = []systemdExecContract{
			contract("/usr/bin/flock", "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-cliproxy bootstrap --portal-config /etc/workagent/portal.json --credential /run/credentials/cliproxyapi.service/cliproxy-management-key --wait 30s", true),
		}
	case "workagent-notification.service":
		pre = []systemdExecContract{
			core, recovery,
			contract("/usr/bin/flock", "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-release verify --root /opt/workagent/control --public-key /etc/workagent/trust/release-signing.pub --scope portal --required-executable bin/workagent-notification --required-executable bin/workagent-release", true),
			contract("/usr/bin/test", "/usr/bin/test -r /etc/workagent/notification.json", false),
		}
		post = []systemdExecContract{
			contract("/usr/bin/curl", "/usr/bin/curl --noproxy * --fail --silent --show-error --max-time 3 http://127.0.0.1:25888/readyz", false),
		}
	case "workagent-chatforward.service":
		pre = []systemdExecContract{
			core, recovery,
			contract("/usr/bin/flock", "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-release verify --root /opt/workagent/control --public-key /etc/workagent/trust/release-signing.pub --scope portal --required-executable bin/workagent-release", true),
			contract("/usr/bin/flock", "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-release verify --root /opt/workagent/shared --public-key /etc/workagent/trust/release-signing.pub --scope shared --required chatforward/app/src/server.js --required-executable chatforward/integration/run-server.sh --required-executable chatforward/node/bin/node --required-executable chatforward/integration/readiness.mjs", true),
		}
		post = []systemdExecContract{
			contract("/opt/workagent/shared/chatforward/node/bin/node", "/opt/workagent/shared/chatforward/node/bin/node --jitless /opt/workagent/shared/chatforward/integration/readiness.mjs --timeout-ms 15000", false),
		}
	case "workagent-chatforward-browser.service":
		pre = []systemdExecContract{
			core, recovery,
			contract("/usr/bin/flock", "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-release verify --root /opt/workagent/control --public-key /etc/workagent/trust/release-signing.pub --scope portal --required-executable bin/workagent-release", true),
			contract("/usr/bin/flock", "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-release verify --root /opt/workagent/shared --public-key /etc/workagent/trust/release-signing.pub --scope shared --required chatforward/app/extension/manifest.json --required-executable chatforward/integration/run-browser.sh --required-executable chatforward/node/bin/node --required-executable chatforward/integration/readiness.mjs", true),
		}
		post = []systemdExecContract{
			contract("/opt/workagent/shared/chatforward/node/bin/node", "/opt/workagent/shared/chatforward/node/bin/node /opt/workagent/shared/chatforward/integration/readiness.mjs --require-controller --timeout-ms 45000", false),
		}
	case "workagent-portal.service":
		pre = []systemdExecContract{
			core, recovery,
			contract("/usr/bin/flock", "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-release verify --root /opt/workagent/control --public-key /etc/workagent/trust/release-signing.pub --scope portal --required-executable bin/workagent-release --required-executable bin/workagent-portal", true),
		}
	case "workagent-backup.service":
		pre = []systemdExecContract{
			core,
			contract("/usr/bin/flock", "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-release verify --root /opt/workagent/control --public-key /etc/workagent/trust/release-signing.pub --scope portal --required-executable bin/workagent-backup --required-executable bin/workagent-release", true),
		}
		stopPost = []systemdExecContract{
			contract("/usr/bin/flock", "/usr/bin/flock --exclusive --nonblock --conflict-exit-code 0 /run/workagent/activation.lock /usr/bin/flock --shared /run/workagent/release-config.lock /usr/bin/flock --shared /opt/workagent/control.lock /opt/workagent/control/bin/workagent-backup resume", false),
		}
	case "workagent-healthcheck.service":
		pre = []systemdExecContract{
			core,
			contract("/usr/bin/flock", "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-release verify --root /opt/workagent/control --public-key /etc/workagent/trust/release-signing.pub --scope portal --required-executable bin/workagent-healthcheck --required-executable bin/workagent-release", true),
		}
	default:
		return false
	}
	return exactCoreManagerExecVector(properties["ExecStartPre"], properties["ExecStartPreEx"], pre) &&
		exactCoreManagerExecVector(properties["ExecStartPost"], properties["ExecStartPostEx"], post) &&
		exactCoreManagerExecVector(properties["ExecStopPost"], properties["ExecStopPostEx"], stopPost) &&
		properties["ExecStop"] == "" && properties["ExecStopEx"] == "" && properties["ExecReload"] == "" && properties["ExecReloadEx"] == ""
}

// VerifyInstalledSystemdSourceFile proves an installed systemd unit source
// file has safe root-owned metadata.
func VerifyInstalledSystemdSourceFile(path string) error {
	info, err := os.Lstat(path)
	stat, ok := fsutil.InfoSyscallStat(info)
	if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
		return errors.New("installed systemd source file metadata is unsafe")
	}
	return nil
}

// VerifyInstalledEdgeAdmissionHelper proves the immutable edge-publication
// admission helper still matches the signed control release.
func VerifyInstalledEdgeAdmissionHelper() error {
	const installed = "/usr/libexec/workagent-edge-publication-admission-v1"
	for _, directory := range []string{"/usr", "/usr/libexec"} {
		info, err := os.Lstat(directory)
		stat, ok := fsutil.InfoSyscallStat(info)
		if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || stat.Uid != 0 || stat.Gid != 0 {
			return errors.Join(fmt.Errorf("immutable edge helper ancestor %s is unsafe", directory), err)
		}
	}
	info, err := os.Lstat(installed)
	stat, ok := fsutil.InfoSyscallStat(info)
	if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o555 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
		return errors.Join(errors.New("installed immutable edge-publication admission helper is unsafe"), err)
	}
	installedDigest, err := release.ProtectedFileSHA256(installed, true)
	if err != nil {
		return err
	}
	reference := filepath.Join(ProductionControlRoot, "share/deploy/libexec/workagent-edge-publication-admission-v1")
	referenceDigest, err := release.ProtectedFileSHA256(reference, true)
	if err != nil || installedDigest != referenceDigest {
		return errors.Join(errors.New("installed edge-publication admission helper does not match the signed control release"), err)
	}
	return nil
}

// VerifyProductionSource authenticates an allow-listed unit's complete
// manager-loaded definition and installed source against the signed control
// release.
func VerifyProductionSource(unit string, properties map[string]string) error {
	if err := verifyServiceActionManagerContract(unit, properties); err != nil {
		return err
	}
	if err := verifySourceAt(unit, properties, ProductionControlRoot, []string{"/etc/systemd/system", "/usr/lib/systemd/system"}); err != nil {
		return err
	}
	if unit != "caddy.service" {
		return nil
	}
	if properties["FragmentPath"] != "/usr/lib/systemd/system/caddy.service" {
		return errors.New("Caddy base unit must be loaded from the exact production systemd namespace")
	}
	if err := VerifyInstalledSystemdSourceFile(properties["FragmentPath"]); err != nil {
		return err
	}
	dropIns := strings.Fields(properties["DropInPaths"])
	if len(dropIns) != 1 || dropIns[0] != "/etc/systemd/system/caddy.service.d/workagent.conf" {
		return errors.New("Caddy installed drop-in set is not exact")
	}
	if err := VerifyInstalledSystemdSourceFile(dropIns[0]); err != nil {
		return err
	}
	binaryInfo, err := os.Lstat("/usr/bin/caddy")
	binaryStat, ok := fsutil.InfoSyscallStat(binaryInfo)
	if err != nil || !ok || binaryInfo.Mode()&os.ModeSymlink != 0 || !binaryInfo.Mode().IsRegular() || binaryInfo.Mode().Perm() != 0o755 || binaryStat.Uid != 0 || binaryStat.Gid != 0 {
		return errors.New("Caddy binary identity is unsafe")
	}
	binaryDigest, err := release.ProtectedFileSHA256("/usr/bin/caddy", true)
	if err != nil || binaryDigest != productionCaddyBinarySHA256 {
		return errors.Join(errors.New("Caddy binary does not match the accepted production build"), err)
	}
	installedConfig, err := release.ProtectedFileSHA256("/etc/caddy/Caddyfile", true)
	if err != nil {
		return err
	}
	signedConfig, err := release.ProtectedFileSHA256(filepath.Join(ProductionControlRoot, "share/deploy/caddy/Caddyfile"), true)
	if err != nil || installedConfig != signedConfig {
		return errors.Join(errors.New("installed Caddy configuration does not match the signed control release"), err)
	}
	return VerifyInstalledEdgeAdmissionHelper()
}

func verifySourceAt(unit string, properties map[string]string, controlRoot string, systemdRoots []string) error {
	if !filepath.IsAbs(controlRoot) || filepath.Clean(controlRoot) != controlRoot || len(systemdRoots) == 0 {
		return errors.New("service-action source verifier layout is invalid")
	}
	var relative string
	switch unit {
	case "cliproxyapi.service", "workagent-backup.service", "workagent-backup.timer", "workagent-healthcheck.service", "workagent-healthcheck.timer", "caddy.service":
		relative = filepath.Join("share", "deploy", "systemd", unit)
	default:
		return errors.New("service-action source unit is not allow-listed")
	}
	fragment := properties["FragmentPath"]
	fragmentAccepted := false
	for _, root := range systemdRoots {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return errors.New("service-action systemd source root is invalid")
		}
		if fragment == filepath.Join(root, unit) {
			fragmentAccepted = true
		}
	}
	if !fragmentAccepted {
		return errors.New("service-action fragment path is outside the authenticated systemd namespace")
	}
	fragmentDigest, err := release.ProtectedFileSHA256(fragment, true)
	if err != nil {
		return err
	}
	referenceDigest, err := release.ProtectedFileSHA256(filepath.Join(controlRoot, relative), true)
	if err != nil || fragmentDigest != referenceDigest {
		return errors.Join(errors.New("service-action fragment does not match the signed control release"), err)
	}
	if unit != "caddy.service" {
		if len(strings.Fields(properties["DropInPaths"])) != 0 {
			return errors.New("service-action unit has an unexpected drop-in")
		}
		return nil
	}
	dropIns := strings.Fields(properties["DropInPaths"])
	dropInAccepted := false
	if len(dropIns) == 1 {
		for _, root := range systemdRoots {
			if dropIns[0] == filepath.Join(root, "caddy.service.d", "workagent.conf") {
				dropInAccepted = true
			}
		}
	}
	if !dropInAccepted {
		return errors.New("Caddy service drop-in namespace is not exact")
	}
	dropInDigest, err := release.ProtectedFileSHA256(dropIns[0], true)
	if err != nil {
		return err
	}
	referenceDigest, err = release.ProtectedFileSHA256(filepath.Join(controlRoot, "share/deploy/systemd/caddy.service.d/workagent.conf"), true)
	if err != nil || dropInDigest != referenceDigest {
		return errors.Join(errors.New("Caddy service drop-in does not match the signed control release"), err)
	}
	return nil
}
