//go:build linux

package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/admin"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

const (
	recoveryProductionControlRoot = "/opt/workagent/control"
	recoveryReleasePublicKey      = "/etc/workagent/trust/release-signing.pub"
	recoverySystemdEtcRoot        = "/etc/systemd/system"
	recoverySystemdVendorRoot     = "/usr/lib/systemd/system"
	recoveryInstalledLibexecRoot  = "/usr/libexec"
	recoveryUnitAssetRoot         = "share/deploy/systemd"
	recoveryLibexecAssetRoot      = "share/deploy/libexec"
	recoveryUnitSourceMaximum     = 1024 * 1024

	recoveryCoreAdmissionPath = "/usr/libexec/workagent-core-activation-admission-v1"
	recoveryAdmissionPath     = "/usr/libexec/workagent-recovery-activation-admission-v1"
	recoveryEdgeAdmissionPath = "/usr/libexec/workagent-edge-publication-admission-v1"
)

var recoverySignedUnitAssets = []string{
	"caddy.service",
	"cliproxyapi.service",
	"srv-workagent-users.mount",
	"workagent-backup.service",
	"workagent-backup.timer",
	"workagent-chatforward-browser.service",
	"workagent-chatforward.service",
	"workagent-healthcheck.service",
	"workagent-healthcheck.timer",
	"workagent-notification.service",
	"workagent-portal.service",
	"workagent-tenant-catalog-ready.target",
	"workagent-tenant-config-reconcile.service",
	"workagent-userhost@.service",
	"workagent-userhost@.socket",
}

var recoverySignedDropInAssets = []string{
	"caddy.service.d/workagent.conf",
	"workagent-portal.service.d/chatforward.conf",
	"workagent-portal.service.d/credentials.conf.example",
}

var recoverySignedLibexecAssets = []string{
	"workagent-core-activation-admission-v1",
	"workagent-edge-publication-admission-v1",
	"workagent-fixed-root-exec-v1",
	"workagent-recovery-activation-admission-v1",
}

type recoverySystemdContractLayout struct {
	controlRoot                string
	publicKey                  string
	systemdRoots               []string
	localDropInRoot            string
	libexecRoot                string
	requireProductionAncestors bool
}

func productionRecoverySystemdContractLayout() recoverySystemdContractLayout {
	return recoverySystemdContractLayout{
		controlRoot:                recoveryProductionControlRoot,
		publicKey:                  recoveryReleasePublicKey,
		systemdRoots:               []string{recoverySystemdEtcRoot, recoverySystemdVendorRoot},
		localDropInRoot:            recoverySystemdEtcRoot,
		libexecRoot:                recoveryInstalledLibexecRoot,
		requireProductionAncestors: true,
	}
}

type recoveryProtectedReference struct {
	path    string
	digest  string
	payload []byte
}

type recoveryContractFileIdentity struct {
	device      uint64
	inode       uint64
	mode        uint32
	uid         uint32
	gid         uint32
	links       uint64
	size        int64
	mtimeSecond int64
	mtimeNano   int64
	ctimeSecond int64
	ctimeNano   int64
}

type recoveryContractSourceSnapshot struct {
	file      recoveryContractFileIdentity
	ancestors map[string]recoveryContractFileIdentity
}

type recoveryExecCommand struct {
	argv          []string
	privileged    bool
	ignoreFailure bool
}

type recoveryUnitCommands struct {
	execStart     []recoveryExecCommand
	execStartPre  []recoveryExecCommand
	execStartPost []recoveryExecCommand
	execStop      []recoveryExecCommand
	execStopPost  []recoveryExecCommand
	execReload    []recoveryExecCommand
	serviceType   string
	user          string
	group         string
	mountWhat     string
	mountWhere    string
	mountType     string
	mountOptions  string
	socketListen  []string
	socketUser    string
	socketGroup   string
	socketMode    string
	directoryMode string
	socketBacklog string
	removeOnStop  string
	socketService string
}

type recoveryDropInBinding struct {
	filename       string
	reference      *recoveryProtectedReference
	expectedDigest string
	exactPath      string
	allowedRoots   []string
}

type recoveryUnitContractSpec struct {
	unit              string
	fragmentAsset     string
	fragment          recoveryProtectedReference
	dropIns           []recoveryDropInBinding
	commands          recoveryUnitCommands
	recoveryActivated bool
}

type recoverySystemdContract struct {
	layout     recoverySystemdContractLayout
	portal     config.Portal
	tenants    []config.Tenant
	units      []string
	specs      map[string]recoveryUnitContractSpec
	helperRefs map[string]recoveryProtectedReference
}

func newProductionRecoverySystemdContract(portal config.Portal, tenants []config.Tenant) (*recoverySystemdContract, error) {
	return newRecoverySystemdContract(portal, tenants, productionRecoverySystemdContractLayout(), true)
}

func newRecoverySystemdContract(portal config.Portal, tenants []config.Tenant, layout recoverySystemdContractLayout, verifySignature bool) (*recoverySystemdContract, error) {
	if err := portal.ValidateProductionLayout("/etc/workagent/portal.json"); err != nil {
		return nil, fmt.Errorf("build recovery systemd contract from Portal policy: %w", err)
	}
	if len(tenants) == 0 || !cleanRecoveryContractLayout(layout) {
		return nil, errors.New("blank-host recovery systemd contract layout is invalid")
	}
	tenants = append([]config.Tenant(nil), tenants...)
	sort.Slice(tenants, func(i, j int) bool { return tenants[i].TenantID < tenants[j].TenantID })
	seenTenants := make(map[string]bool, len(tenants))
	for _, tenant := range tenants {
		if tenant.TenantID == "" || seenTenants[tenant.TenantID] {
			return nil, errors.New("blank-host recovery systemd contract tenant set is invalid")
		}
		if err := admin.ValidateTenantBinding(portal, tenant); err != nil {
			return nil, fmt.Errorf("blank-host recovery systemd contract tenant %s is invalid: %w", tenant.TenantID, err)
		}
		seenTenants[tenant.TenantID] = true
	}
	required := make([]string, 0, len(recoverySignedUnitAssets)+len(recoverySignedDropInAssets))
	for _, asset := range recoverySignedUnitAssets {
		required = append(required, filepath.ToSlash(filepath.Join(recoveryUnitAssetRoot, asset)))
	}
	for _, asset := range recoverySignedDropInAssets {
		required = append(required, filepath.ToSlash(filepath.Join(recoveryUnitAssetRoot, asset)))
	}
	requiredExecutables := make([]string, 0, len(recoverySignedLibexecAssets))
	for _, asset := range recoverySignedLibexecAssets {
		requiredExecutables = append(requiredExecutables, filepath.ToSlash(filepath.Join(recoveryLibexecAssetRoot, asset)))
	}
	sort.Strings(required)
	sort.Strings(requiredExecutables)
	if verifySignature {
		if _, err := release.Verify(layout.controlRoot, filepath.Join(layout.controlRoot, "manifest.json"), release.VerifyOptions{
			RequiredPaths: required, RequiredExecutablePaths: requiredExecutables,
			RequireRootOwner: true, RequireSignature: true,
			SignaturePath: filepath.Join(layout.controlRoot, "manifest.sig"), PublicKeyPath: layout.publicKey,
			AllowedScopes: []string{release.ScopePortal},
		}); err != nil {
			return nil, fmt.Errorf("authenticate signed control unit assets for blank-host recovery: %w", err)
		}
	}
	references := make(map[string]recoveryProtectedReference, len(required)+len(requiredExecutables))
	for _, relative := range append(append([]string(nil), required...), requiredExecutables...) {
		reference, err := loadRecoveryProtectedReference(filepath.Join(layout.controlRoot, filepath.FromSlash(relative)))
		if err != nil {
			return nil, fmt.Errorf("load signed recovery contract asset %s: %w", relative, err)
		}
		references[relative] = reference
	}
	contract := &recoverySystemdContract{
		layout: layout, portal: portal, tenants: tenants,
		specs:      make(map[string]recoveryUnitContractSpec, 12+len(tenants)*2),
		helperRefs: make(map[string]recoveryProtectedReference, len(recoverySignedLibexecAssets)),
	}
	for _, name := range recoverySignedLibexecAssets {
		relative := filepath.ToSlash(filepath.Join(recoveryLibexecAssetRoot, name))
		contract.helperRefs[filepath.Join(layout.libexecRoot, name)] = references[relative]
	}
	portalCredentials, err := recoveryPortalCredentialsPayload(portal, references[filepath.ToSlash(filepath.Join(recoveryUnitAssetRoot, "workagent-portal.service.d/credentials.conf.example"))].payload)
	if err != nil {
		return nil, err
	}
	coreUnits := []string{
		"srv-workagent-users.mount",
		"cliproxyapi.service",
		"workagent-notification.service",
		"workagent-chatforward.service",
		"workagent-chatforward-browser.service",
		"workagent-portal.service",
		"workagent-tenant-catalog-ready.target",
		"workagent-tenant-config-reconcile.service",
		"caddy.service",
		"workagent-backup.service",
		"workagent-backup.timer",
		"workagent-healthcheck.service",
		"workagent-healthcheck.timer",
	}
	for _, unit := range coreUnits {
		spec, err := contract.buildUnitSpec(unit, config.Tenant{}, references, portalCredentials)
		if err != nil {
			return nil, err
		}
		contract.units = append(contract.units, unit)
		contract.specs[unit] = spec
	}
	for _, tenant := range tenants {
		for _, suffix := range []string{".service", ".socket"} {
			unit := "workagent-userhost@" + tenant.TenantID + suffix
			spec, err := contract.buildUnitSpec(unit, tenant, references, portalCredentials)
			if err != nil {
				return nil, err
			}
			contract.units = append(contract.units, unit)
			contract.specs[unit] = spec
		}
	}
	return contract, nil
}

func cleanRecoveryContractLayout(layout recoverySystemdContractLayout) bool {
	if !cleanAbsolute(layout.controlRoot) || !cleanAbsolute(layout.publicKey) || !cleanAbsolute(layout.localDropInRoot) || !cleanAbsolute(layout.libexecRoot) || len(layout.systemdRoots) == 0 {
		return false
	}
	seen := make(map[string]bool, len(layout.systemdRoots))
	for _, root := range layout.systemdRoots {
		if !cleanAbsolute(root) || seen[root] {
			return false
		}
		seen[root] = true
	}
	return true
}

func (contract *recoverySystemdContract) buildUnitSpec(unit string, tenant config.Tenant, references map[string]recoveryProtectedReference, portalCredentials []byte) (recoveryUnitContractSpec, error) {
	asset := unit
	recoveryActivated := false
	var dropIns []recoveryDropInBinding
	switch {
	case strings.HasPrefix(unit, "workagent-userhost@") && strings.HasSuffix(unit, ".service"):
		asset = "workagent-userhost@.service"
		recoveryActivated = true
		base := filepath.Join(contract.layout.localDropInRoot, unit+".d")
		identity := recoveryTenantIdentityPayload(tenant)
		resources := recoveryTenantResourcesPayload(tenant)
		dropIns = []recoveryDropInBinding{
			{filename: "identity.conf", exactPath: filepath.Join(base, "identity.conf"), expectedDigest: recoveryPayloadSHA256(identity)},
			{filename: "resources.conf", exactPath: filepath.Join(base, "resources.conf"), expectedDigest: recoveryPayloadSHA256(resources)},
		}
	case strings.HasPrefix(unit, "workagent-userhost@") && strings.HasSuffix(unit, ".socket"):
		asset = "workagent-userhost@.socket"
	case unit == "cliproxyapi.service" || unit == "workagent-notification.service" || unit == "workagent-chatforward.service" ||
		unit == "workagent-chatforward-browser.service" || unit == "workagent-portal.service" || unit == "workagent-tenant-config-reconcile.service":
		recoveryActivated = true
	}
	if unit == "caddy.service" {
		reference := references[filepath.ToSlash(filepath.Join(recoveryUnitAssetRoot, "caddy.service.d/workagent.conf"))]
		dropIns = append(dropIns, recoveryDropInBinding{filename: "workagent.conf", reference: &reference, allowedRoots: append([]string(nil), contract.layout.systemdRoots...)})
	}
	if unit == "workagent-portal.service" {
		chat := references[filepath.ToSlash(filepath.Join(recoveryUnitAssetRoot, "workagent-portal.service.d/chatforward.conf"))]
		dropIns = append(dropIns,
			recoveryDropInBinding{filename: "chatforward.conf", reference: &chat, allowedRoots: append([]string(nil), contract.layout.systemdRoots...)},
			recoveryDropInBinding{filename: "credentials.conf", exactPath: filepath.Join(contract.layout.localDropInRoot, "workagent-portal.service.d", "credentials.conf"), expectedDigest: recoveryPayloadSHA256(portalCredentials)},
		)
	}
	fragmentRelative := filepath.ToSlash(filepath.Join(recoveryUnitAssetRoot, asset))
	fragment, ok := references[fragmentRelative]
	if !ok {
		return recoveryUnitContractSpec{}, fmt.Errorf("signed recovery unit fragment %s is unavailable", asset)
	}
	payloads := [][]byte{fragment.payload}
	sortedDropIns := append([]recoveryDropInBinding(nil), dropIns...)
	sort.Slice(sortedDropIns, func(i, j int) bool { return sortedDropIns[i].filename < sortedDropIns[j].filename })
	for _, binding := range sortedDropIns {
		if binding.reference != nil {
			payloads = append(payloads, binding.reference.payload)
			continue
		}
		switch binding.filename {
		case "credentials.conf":
			payloads = append(payloads, portalCredentials)
		case "identity.conf":
			payloads = append(payloads, recoveryTenantIdentityPayload(tenant))
		case "resources.conf":
			payloads = append(payloads, recoveryTenantResourcesPayload(tenant))
		default:
			return recoveryUnitContractSpec{}, errors.New("recovery systemd contract contains an unknown dynamic drop-in")
		}
	}
	commands, err := parseRecoveryUnitCommands(payloads...)
	if err != nil {
		return recoveryUnitContractSpec{}, fmt.Errorf("parse signed effective command contract for %s: %w", unit, err)
	}
	if strings.HasSuffix(unit, ".service") {
		if len(commands.execStart) != 1 || commands.serviceType == "" || commands.user == "" || commands.group == "" {
			return recoveryUnitContractSpec{}, fmt.Errorf("signed service command or identity contract for %s is incomplete", unit)
		}
	} else if len(commands.execStart) != 0 || len(commands.execStartPre) != 0 || len(commands.execStartPost) != 0 ||
		len(commands.execStop) != 0 || len(commands.execStopPost) != 0 || len(commands.execReload) != 0 {
		return recoveryUnitContractSpec{}, fmt.Errorf("non-service recovery unit %s unexpectedly defines service commands", unit)
	}
	if strings.HasSuffix(unit, ".mount") && (commands.mountWhat == "" || commands.mountWhere == "" || commands.mountType == "" || commands.mountOptions == "") {
		return recoveryUnitContractSpec{}, fmt.Errorf("signed mount contract for %s is incomplete", unit)
	}
	if strings.HasSuffix(unit, ".socket") && (len(commands.socketListen) != 1 || commands.socketUser == "" || commands.socketGroup == "" || commands.socketMode == "" ||
		commands.directoryMode == "" || commands.socketBacklog == "" || commands.removeOnStop == "" || commands.socketService == "") {
		return recoveryUnitContractSpec{}, fmt.Errorf("signed socket contract for %s is incomplete", unit)
	}
	if err := validateRecoveryAdmissionCommandOrder(unit, commands.execStartPre, recoveryActivated); err != nil {
		return recoveryUnitContractSpec{}, err
	}
	return recoveryUnitContractSpec{
		unit: unit, fragmentAsset: asset, fragment: fragment, dropIns: dropIns,
		commands: commands, recoveryActivated: recoveryActivated,
	}, nil
}

func recoveryPortalCredentialsPayload(portal config.Portal, example []byte) ([]byte, error) {
	if len(example) == 0 || len(example) > recoveryUnitSourceMaximum {
		return nil, errors.New("signed Portal credential-drop-in template is invalid")
	}
	payload := append([]byte(nil), example...)
	const commented = "# LoadCredentialEncrypted=admin-master-password-hash:/etc/credstore.encrypted/workagent/admin-master-password-hash.cred"
	const enabled = "LoadCredentialEncrypted=admin-master-password-hash:/etc/credstore.encrypted/workagent/admin-master-password-hash.cred"
	if bytes.Count(payload, []byte(commented)) != 1 {
		return nil, errors.New("signed Portal credential template optional administrator line is not exact")
	}
	if portal.AdminMasterPasswordHashFile != "" {
		payload = bytes.Replace(payload, []byte(commented), []byte(enabled), 1)
	}
	return payload, nil
}

func recoveryTenantIdentityPayload(tenant config.Tenant) []byte {
	return []byte("[Service]\nUser=" + tenant.RuntimeUser + "\nGroup=" + tenant.RuntimeUser + "\n")
}

func recoveryTenantResourcesPayload(tenant config.Tenant) []byte {
	return admin.ResourceDropInPayload(tenant.Limits.Effective())
}

func validateRecoveryAdmissionCommandOrder(unit string, commands []recoveryExecCommand, recoveryActivated bool) error {
	paths := make([]string, len(commands))
	for index, command := range commands {
		if len(command.argv) == 0 {
			return fmt.Errorf("signed pre-start command contract for %s is empty", unit)
		}
		paths[index] = command.argv[0]
	}
	requirePrefix := func(expected ...string) error {
		if len(paths) < len(expected) {
			return fmt.Errorf("signed admission command contract for %s is incomplete", unit)
		}
		for index, path := range expected {
			if paths[index] != path || !commands[index].privileged || commands[index].ignoreFailure {
				return fmt.Errorf("signed admission command order for %s is not exact", unit)
			}
		}
		return nil
	}
	if recoveryActivated {
		return requirePrefix(recoveryCoreAdmissionPath, recoveryAdmissionPath)
	}
	switch unit {
	case "caddy.service":
		return requirePrefix(recoveryCoreAdmissionPath, recoveryEdgeAdmissionPath)
	case "workagent-backup.service", "workagent-healthcheck.service":
		return requirePrefix(recoveryCoreAdmissionPath)
	}
	return nil
}

func parseRecoveryUnitCommands(payloads ...[]byte) (recoveryUnitCommands, error) {
	var result recoveryUnitCommands
	for _, payload := range payloads {
		if len(payload) == 0 || len(payload) > recoveryUnitSourceMaximum || bytes.IndexByte(payload, 0) >= 0 {
			return recoveryUnitCommands{}, errors.New("systemd unit command source is invalid")
		}
		section := ""
		lines := strings.Split(string(payload), "\n")
		for index := 0; index < len(lines); index++ {
			line := strings.TrimSpace(strings.TrimSuffix(lines[index], "\r"))
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				section = strings.TrimSpace(line[1 : len(line)-1])
				continue
			}
			if section == "Mount" {
				key, value, found := strings.Cut(line, "=")
				if !found {
					return recoveryUnitCommands{}, errors.New("systemd mount directive is malformed")
				}
				key, value = strings.TrimSpace(key), strings.TrimSpace(value)
				switch key {
				case "What":
					result.mountWhat = value
				case "Where":
					result.mountWhere = value
				case "Type":
					result.mountType = value
				case "Options":
					result.mountOptions = value
				}
				continue
			}
			if section == "Socket" {
				key, value, found := strings.Cut(line, "=")
				if !found {
					return recoveryUnitCommands{}, errors.New("systemd socket directive is malformed")
				}
				key, value = strings.TrimSpace(key), strings.TrimSpace(value)
				switch key {
				case "ListenStream":
					if value == "" {
						result.socketListen = nil
					} else {
						result.socketListen = append(result.socketListen, value)
					}
				case "SocketUser":
					result.socketUser = value
				case "SocketGroup":
					result.socketGroup = value
				case "SocketMode":
					result.socketMode = value
				case "DirectoryMode":
					result.directoryMode = value
				case "Backlog":
					result.socketBacklog = value
				case "RemoveOnStop":
					result.removeOnStop = value
				case "Service":
					result.socketService = value
				}
				continue
			}
			if section != "Service" {
				continue
			}
			key, value, found := strings.Cut(line, "=")
			if !found {
				return recoveryUnitCommands{}, errors.New("systemd service directive is malformed")
			}
			key, value = strings.TrimSpace(key), strings.TrimSpace(value)
			var target *[]recoveryExecCommand
			switch key {
			case "ExecStart":
				target = &result.execStart
			case "ExecStartPre":
				target = &result.execStartPre
			case "ExecStartPost":
				target = &result.execStartPost
			case "ExecStop":
				target = &result.execStop
			case "ExecStopPost":
				target = &result.execStopPost
			case "ExecReload":
				target = &result.execReload
			case "Type":
				result.serviceType = value
			case "User":
				result.user = value
			case "Group":
				result.group = value
			}
			if target == nil {
				continue
			}
			if value == "" {
				*target = nil
				continue
			}
			command, err := parseRecoverySystemdCommand(value)
			if err != nil {
				return recoveryUnitCommands{}, err
			}
			*target = append(*target, command)
		}
	}
	return result, nil
}

func parseRecoverySystemdCommand(value string) (recoveryExecCommand, error) {
	argv, err := splitRecoverySystemdWords(value)
	if err != nil || len(argv) == 0 {
		return recoveryExecCommand{}, errors.New("systemd command line is invalid")
	}
	command := recoveryExecCommand{}
	for len(argv[0]) > 0 {
		switch argv[0][0] {
		case '+':
			if command.privileged {
				return recoveryExecCommand{}, errors.New("systemd command repeats the privileged prefix")
			}
			command.privileged = true
			argv[0] = argv[0][1:]
		case '-':
			if command.ignoreFailure {
				return recoveryExecCommand{}, errors.New("systemd command repeats the ignore-failure prefix")
			}
			command.ignoreFailure = true
			argv[0] = argv[0][1:]
		default:
			goto prefixesDone
		}
	}
prefixesDone:
	if argv[0] == "" || !filepath.IsAbs(argv[0]) || filepath.Clean(argv[0]) != argv[0] {
		return recoveryExecCommand{}, errors.New("systemd command executable is not an exact absolute path")
	}
	for _, argument := range argv {
		if strings.ContainsAny(argument, "\x00\r\n") {
			return recoveryExecCommand{}, errors.New("systemd command argument contains a control character")
		}
	}
	command.argv = argv
	return command, nil
}

func splitRecoverySystemdWords(value string) ([]string, error) {
	var words []string
	var word strings.Builder
	quote := rune(0)
	escaped := false
	started := false
	flush := func() {
		if started {
			words = append(words, word.String())
			word.Reset()
			started = false
		}
	}
	for _, character := range value {
		if escaped {
			word.WriteRune(character)
			started = true
			escaped = false
			continue
		}
		if character == '\\' && quote != '\'' {
			escaped = true
			started = true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
				started = true
			} else {
				word.WriteRune(character)
				started = true
			}
			continue
		}
		switch character {
		case '\'', '"':
			quote = character
			started = true
		case ' ', '\t':
			flush()
		default:
			word.WriteRune(character)
			started = true
		}
	}
	if escaped || quote != 0 {
		return nil, errors.New("systemd command quoting is incomplete")
	}
	flush()
	return words, nil
}

func (contract *recoverySystemdContract) baselineUnitFileStates() map[string]string {
	states := make(map[string]string, len(contract.units))
	for _, unit := range contract.units {
		switch {
		case unit == "srv-workagent-users.mount":
			states[unit] = "enabled"
		case unit == "workagent-backup.service" || unit == "workagent-healthcheck.service" ||
			unit == "workagent-tenant-catalog-ready.target" || unit == "workagent-tenant-config-reconcile.service" ||
			(strings.HasPrefix(unit, "workagent-userhost@") && strings.HasSuffix(unit, ".service")):
			states[unit] = "static"
		default:
			states[unit] = "disabled"
		}
	}
	return states
}

func (contract *recoverySystemdContract) activatedUnitFileStates(journal recoveryActivationJournal) (map[string]string, error) {
	if err := validateRecoveryActivationJournal(journal); err != nil {
		return nil, err
	}
	states := contract.baselineUnitFileStates()
	for _, unit := range recoveryActivationEnableUnits(journal) {
		if states[unit] != "disabled" {
			return nil, fmt.Errorf("recovery activation journal unit %s has no disabled baseline", unit)
		}
		states[unit] = "enabled"
	}
	return states, nil
}

func (contract *recoverySystemdContract) requireFleet(ctx context.Context, controller systemdctl.Controller, states map[string]string) error {
	if contract == nil || controller == nil || len(contract.units) == 0 || len(states) != len(contract.units) {
		return errors.New("blank-host recovery full systemd contract proof is unavailable")
	}
	if err := requireExactRecoveryTenantUnits(ctx, controller, contract.tenants); err != nil {
		return err
	}
	for _, unit := range contract.units {
		if err := contract.requireUnit(ctx, controller, unit, states[unit]); err != nil {
			return err
		}
	}
	return nil
}

func (contract *recoverySystemdContract) requireUnits(ctx context.Context, controller systemdctl.Controller, states map[string]string, units ...string) error {
	if contract == nil || controller == nil || len(units) == 0 {
		return errors.New("blank-host recovery systemd contract subset proof is unavailable")
	}
	seen := make(map[string]bool, len(units))
	for _, unit := range units {
		if seen[unit] || states[unit] == "" {
			return errors.New("blank-host recovery systemd contract subset is invalid")
		}
		seen[unit] = true
		if err := contract.requireUnit(ctx, controller, unit, states[unit]); err != nil {
			return err
		}
	}
	return nil
}

func (contract *recoverySystemdContract) requireUnit(ctx context.Context, controller systemdctl.Controller, unit, expectedUnitFileState string) error {
	spec, ok := contract.specs[unit]
	if !ok || (expectedUnitFileState != "disabled" && expectedUnitFileState != "enabled" && expectedUnitFileState != "static") {
		return errors.New("blank-host recovery systemd unit contract is invalid")
	}
	propertyNames := []string{"LoadState", "UnitFileState", "FragmentPath", "DropInPaths", "NeedDaemonReload"}
	if strings.HasSuffix(unit, ".service") {
		propertyNames = append(propertyNames,
			"Type", "User", "Group", "ExecStart", "ExecStartEx", "ExecStartPre", "ExecStartPreEx", "ExecStartPost", "ExecStartPostEx",
			"ExecStop", "ExecStopEx", "ExecStopPost", "ExecStopPostEx", "ExecReload", "ExecReloadEx",
		)
	} else if strings.HasSuffix(unit, ".mount") {
		propertyNames = append(propertyNames, "What", "Where", "Type", "Options")
	} else if strings.HasSuffix(unit, ".socket") {
		propertyNames = append(propertyNames, "Listen", "SocketUser", "SocketGroup", "SocketMode", "DirectoryMode", "Backlog", "RemoveOnStop", "Accept", "Triggers")
	}
	before, err := controller.Properties(ctx, unit, propertyNames...)
	if err != nil {
		return fmt.Errorf("inspect manager-loaded recovery unit contract for %s: %w", unit, err)
	}
	if err := contract.validateManagerUnit(spec, before, expectedUnitFileState); err != nil {
		return err
	}
	beforeSources, err := contract.authenticateUnitSources(spec, before)
	if err != nil {
		return fmt.Errorf("authenticate package-prepared source for %s: %w", unit, err)
	}
	after, err := controller.Properties(ctx, unit, propertyNames...)
	if err != nil || !reflect.DeepEqual(before, after) {
		return errors.Join(fmt.Errorf("manager-loaded recovery unit %s changed during exact source authentication", unit), err)
	}
	if err := contract.validateManagerUnit(spec, after, expectedUnitFileState); err != nil {
		return err
	}
	afterSources, err := contract.authenticateUnitSources(spec, after)
	if err != nil {
		return fmt.Errorf("re-authenticate package-prepared source for %s: %w", unit, err)
	}
	if !reflect.DeepEqual(beforeSources, afterSources) {
		return fmt.Errorf("installed recovery unit source or ancestor identity for %s changed between exact manager reads", unit)
	}
	return nil
}

func (contract *recoverySystemdContract) validateManagerUnit(spec recoveryUnitContractSpec, properties map[string]string, expectedUnitFileState string) error {
	if properties["LoadState"] != "loaded" || properties["UnitFileState"] != expectedUnitFileState || properties["NeedDaemonReload"] != "no" {
		return fmt.Errorf("manager-loaded recovery unit %s is not loaded from a current daemon cache with UnitFileState=%s", spec.unit, expectedUnitFileState)
	}
	if strings.HasSuffix(spec.unit, ".mount") {
		if properties["What"] != spec.commands.mountWhat || properties["Where"] != spec.commands.mountWhere ||
			properties["Type"] != spec.commands.mountType || properties["Options"] != spec.commands.mountOptions {
			return fmt.Errorf("manager-loaded mount semantics for %s differ from the signed unit asset", spec.unit)
		}
		return nil
	}
	if strings.HasSuffix(spec.unit, ".socket") {
		listen, err := expandRecoverySystemdSpecifiers(spec.commands.socketListen[0], spec.unit)
		if err != nil {
			return err
		}
		service, err := expandRecoverySystemdSpecifiers(spec.commands.socketService, spec.unit)
		if err != nil {
			return err
		}
		if properties["Listen"] != listen+" (Stream)" || properties["SocketUser"] != spec.commands.socketUser ||
			properties["SocketGroup"] != spec.commands.socketGroup || properties["SocketMode"] != spec.commands.socketMode ||
			properties["DirectoryMode"] != spec.commands.directoryMode || properties["Backlog"] != spec.commands.socketBacklog ||
			properties["RemoveOnStop"] != spec.commands.removeOnStop || properties["Accept"] != "no" || properties["Triggers"] != service {
			return fmt.Errorf("manager-loaded socket semantics for %s differ from the signed unit asset", spec.unit)
		}
		return nil
	}
	if !strings.HasSuffix(spec.unit, ".service") {
		return nil
	}
	if properties["Type"] != spec.commands.serviceType || properties["User"] != spec.commands.user || properties["Group"] != spec.commands.group {
		return fmt.Errorf("manager-loaded recovery service identity for %s differs from the signed unit assets", spec.unit)
	}
	checks := []struct {
		property string
		value    string
		commands []recoveryExecCommand
		extended bool
	}{
		{"ExecStart", properties["ExecStart"], spec.commands.execStart, false},
		{"ExecStartEx", properties["ExecStartEx"], spec.commands.execStart, true},
		{"ExecStartPre", properties["ExecStartPre"], spec.commands.execStartPre, false},
		{"ExecStartPreEx", properties["ExecStartPreEx"], spec.commands.execStartPre, true},
		{"ExecStartPost", properties["ExecStartPost"], spec.commands.execStartPost, false},
		{"ExecStartPostEx", properties["ExecStartPostEx"], spec.commands.execStartPost, true},
		{"ExecStop", properties["ExecStop"], spec.commands.execStop, false},
		{"ExecStopEx", properties["ExecStopEx"], spec.commands.execStop, true},
		{"ExecStopPost", properties["ExecStopPost"], spec.commands.execStopPost, false},
		{"ExecStopPostEx", properties["ExecStopPostEx"], spec.commands.execStopPost, true},
		{"ExecReload", properties["ExecReload"], spec.commands.execReload, false},
		{"ExecReloadEx", properties["ExecReloadEx"], spec.commands.execReload, true},
	}
	for _, check := range checks {
		if !matchRecoveryManagerExecSequence(check.value, check.commands, spec.unit, check.extended) {
			return fmt.Errorf("manager-loaded %s for %s differs from the complete signed command sequence", check.property, spec.unit)
		}
	}
	return nil
}

func matchRecoveryManagerExecSequence(value string, expected []recoveryExecCommand, unit string, extended bool) bool {
	rest := strings.TrimSpace(value)
	if len(expected) == 0 {
		return rest == ""
	}
	if strings.Count(rest, "{ path=") != len(expected) {
		return false
	}
	for _, command := range expected {
		if !strings.HasPrefix(rest, "{ path=") {
			return false
		}
		alternatives, err := recoveryManagerCommandAlternatives(command, unit)
		if err != nil {
			return false
		}
		matchedPrefix := ""
		for _, alternative := range alternatives {
			prefix := "{ path=" + alternative[0] + " ; argv[]=" + alternative[1] + " ;"
			if strings.HasPrefix(rest, prefix) && len(prefix) > len(matchedPrefix) {
				matchedPrefix = prefix
			}
		}
		if matchedPrefix == "" {
			return false
		}
		end := strings.Index(rest[len(matchedPrefix):], " }")
		if end < 0 {
			return false
		}
		end += len(matchedPrefix)
		body := rest[len(matchedPrefix):end]
		if strings.Contains(body, "{ path=") {
			return false
		}
		if extended {
			var flags []string
			if command.ignoreFailure {
				flags = append(flags, "ignore-failure")
			}
			if command.privileged {
				flags = append(flags, "privileged")
			}
			if !strings.HasPrefix(body, " flags="+strings.Join(flags, " ")+" ;") {
				return false
			}
		} else {
			expectedIgnore := "ignore_errors=no ;"
			if command.ignoreFailure {
				expectedIgnore = "ignore_errors=yes ;"
			}
			if !strings.Contains(body, expectedIgnore) {
				return false
			}
		}
		rest = strings.TrimSpace(rest[end+2:])
		if strings.HasPrefix(rest, ";") {
			rest = strings.TrimSpace(rest[1:])
		}
	}
	return rest == ""
}

// Each result is [executable, flattened argv]. The production manager is
// pinned to systemd 255, whose Exec* and Exec*Ex properties expose expanded
// command specifiers. Accepting the unit-file spelling as an alternative would
// make this manager-memory proof wider than the pinned production contract.
func recoveryManagerCommandAlternatives(command recoveryExecCommand, unit string) ([][2]string, error) {
	if len(command.argv) == 0 {
		return nil, errors.New("empty recovery manager command")
	}
	expanded := make([]string, len(command.argv))
	for index, argument := range command.argv {
		value, err := expandRecoverySystemdSpecifiers(argument, unit)
		if err != nil {
			return nil, err
		}
		expanded[index] = value
	}
	return [][2]string{{expanded[0], strings.Join(expanded, " ")}}, nil
}

func expandRecoverySystemdSpecifiers(value, unit string) (string, error) {
	instance := ""
	prefix := strings.TrimSuffix(unit, filepath.Ext(unit))
	if at := strings.Index(prefix, "@"); at >= 0 {
		instance = prefix[at+1:]
		prefix = prefix[:at]
	}
	var output strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '%' {
			output.WriteByte(value[index])
			continue
		}
		index++
		if index >= len(value) {
			return "", errors.New("systemd command ends in an incomplete specifier")
		}
		switch value[index] {
		case '%':
			output.WriteByte('%')
		case 'i', 'I':
			if instance == "" {
				return "", errors.New("systemd instance specifier is used by a non-instance unit")
			}
			output.WriteString(instance)
		case 'n', 'N':
			output.WriteString(unit)
		case 'p':
			output.WriteString(prefix)
		case 'd':
			output.WriteString(filepath.Join("/run/credentials", unit))
		default:
			return "", fmt.Errorf("unsupported systemd command specifier %%%c", value[index])
		}
	}
	return output.String(), nil
}

func (contract *recoverySystemdContract) authenticateUnitSources(spec recoveryUnitContractSpec, properties map[string]string) (map[string]recoveryContractSourceSnapshot, error) {
	snapshots := make(map[string]recoveryContractSourceSnapshot, 1+len(spec.dropIns)+len(contract.helperRefs))
	capture := func(path, digest string, mode os.FileMode, root string) error {
		if _, duplicate := snapshots[path]; duplicate {
			return errors.New("recovery unit source contract contains a duplicate path")
		}
		snapshot, err := captureRecoverySourceDigest(path, digest, mode, root, contract.layout.requireProductionAncestors)
		if err != nil {
			return err
		}
		snapshots[path] = snapshot
		return nil
	}
	fragment := properties["FragmentPath"]
	fragmentAllowed := false
	fragmentRoot := ""
	for _, root := range contract.layout.systemdRoots {
		if fragment == filepath.Join(root, spec.fragmentAsset) {
			fragmentAllowed = true
			fragmentRoot = root
		}
	}
	if spec.unit == "caddy.service" && fragment != filepath.Join(recoverySystemdVendorRoot, "caddy.service") {
		fragmentAllowed = false
	}
	if !fragmentAllowed {
		return nil, errors.New("systemd fragment path is outside the exact package namespace")
	}
	if err := capture(fragment, spec.fragment.digest, 0o644, fragmentRoot); err != nil {
		return nil, err
	}
	if err := verifyRecoveryReferenceStable(spec.fragment); err != nil {
		return nil, err
	}
	actualDropIns := strings.Fields(properties["DropInPaths"])
	if len(actualDropIns) != len(spec.dropIns) {
		return nil, errors.New("systemd drop-in set is not exact")
	}
	seen := make(map[string]bool, len(actualDropIns))
	for _, path := range actualDropIns {
		if seen[path] {
			return nil, errors.New("systemd drop-in set contains a duplicate")
		}
		seen[path] = true
		matched := false
		for _, binding := range spec.dropIns {
			matchedRoot := recoveryDropInPathRoot(spec.unit, path, binding, contract.layout.localDropInRoot)
			if matchedRoot == "" {
				continue
			}
			digest := binding.expectedDigest
			if binding.reference != nil {
				digest = binding.reference.digest
				if err := verifyRecoveryReferenceStable(*binding.reference); err != nil {
					return nil, err
				}
			}
			if digest == "" {
				return nil, errors.New("systemd drop-in expected digest is unavailable")
			}
			if err := capture(path, digest, 0o644, matchedRoot); err != nil {
				return nil, err
			}
			matched = true
			break
		}
		if !matched {
			return nil, errors.New("systemd drop-in path is outside the exact package namespace")
		}
	}
	for _, commandSet := range [][]recoveryExecCommand{
		spec.commands.execStart,
		spec.commands.execStartPre,
		spec.commands.execStartPost,
		spec.commands.execStop,
		spec.commands.execStopPost,
		spec.commands.execReload,
	} {
		for _, command := range commandSet {
			if len(command.argv) == 0 {
				return nil, errors.New("signed systemd command is empty")
			}
			reference, ok := contract.helperRefs[command.argv[0]]
			if !ok {
				continue
			}
			if _, already := snapshots[command.argv[0]]; !already {
				if err := capture(command.argv[0], reference.digest, 0o555, contract.layout.libexecRoot); err != nil {
					return nil, fmt.Errorf("authenticate installed immutable helper %s: %w", command.argv[0], err)
				}
			}
			if err := verifyRecoveryReferenceStable(reference); err != nil {
				return nil, err
			}
		}
	}
	return snapshots, nil
}

func recoveryDropInPathRoot(unit, path string, binding recoveryDropInBinding, localDropInRoot string) string {
	if binding.exactPath != "" {
		if path == binding.exactPath {
			return localDropInRoot
		}
		return ""
	}
	for _, root := range binding.allowedRoots {
		if path == filepath.Join(root, unit+".d", binding.filename) {
			return root
		}
	}
	return ""
}

func loadRecoveryProtectedReference(path string) (recoveryProtectedReference, error) {
	digest, err := release.ProtectedFileSHA256(path, true)
	if err != nil {
		return recoveryProtectedReference{}, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return recoveryProtectedReference{}, err
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, recoveryUnitSourceMaximum+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(payload) == 0 || len(payload) > recoveryUnitSourceMaximum || recoveryPayloadSHA256(payload) != digest {
		return recoveryProtectedReference{}, errors.Join(errors.New("signed recovery contract reference changed while read"), readErr, closeErr)
	}
	after, err := release.ProtectedFileSHA256(path, true)
	if err != nil || after != digest {
		return recoveryProtectedReference{}, errors.Join(errors.New("signed recovery contract reference changed after read"), err)
	}
	return recoveryProtectedReference{path: path, digest: digest, payload: payload}, nil
}

func verifyRecoveryReferenceStable(reference recoveryProtectedReference) error {
	if reference.path == "" || reference.digest == "" || len(reference.payload) == 0 || recoveryPayloadSHA256(reference.payload) != reference.digest {
		return errors.New("signed recovery contract reference snapshot is invalid")
	}
	digest, err := release.ProtectedFileSHA256(reference.path, true)
	if err != nil || digest != reference.digest {
		return errors.Join(errors.New("signed recovery contract reference changed after authentication"), err)
	}
	return nil
}

func verifyRecoverySourceDigest(path, expected string, mode os.FileMode, namespaceRoot string, requireProductionAncestors bool) error {
	_, err := captureRecoverySourceDigest(path, expected, mode, namespaceRoot, requireProductionAncestors)
	return err
}

func captureRecoverySourceDigest(path, expected string, mode os.FileMode, namespaceRoot string, requireProductionAncestors bool) (recoveryContractSourceSnapshot, error) {
	if !cleanAbsolute(path) || !cleanAbsolute(namespaceRoot) || !recoveryPathWithinRoot(path, namespaceRoot) || expected == "" || (mode != 0o644 && mode != 0o555) {
		return recoveryContractSourceSnapshot{}, errors.New("installed recovery unit source expectation is invalid")
	}
	beforeAncestors, err := captureRecoverySourceAncestors(path, namespaceRoot, requireProductionAncestors)
	if err != nil {
		return recoveryContractSourceSnapshot{}, err
	}
	beforeInfo, err := os.Lstat(path)
	if err != nil {
		return recoveryContractSourceSnapshot{}, err
	}
	before, ok := beforeInfo.Sys().(*syscall.Stat_t)
	if !ok || beforeInfo.Mode()&os.ModeSymlink != 0 || !beforeInfo.Mode().IsRegular() || beforeInfo.Mode().Perm() != mode ||
		before.Uid != 0 || before.Gid != 0 || before.Nlink != 1 || beforeInfo.Size() <= 0 || beforeInfo.Size() > recoveryUnitSourceMaximum {
		return recoveryContractSourceSnapshot{}, errors.New("installed recovery unit source metadata is unsafe")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return recoveryContractSourceSnapshot{}, errors.New("open installed recovery unit source without linked traversal")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var opened syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &opened); err != nil || !sameRecoveryContractStat(*before, opened) {
		return recoveryContractSourceSnapshot{}, errors.New("installed recovery unit source changed while opening")
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, recoveryUnitSourceMaximum+1))
	if err != nil || written != beforeInfo.Size() || fmt.Sprintf("%x", hash.Sum(nil)) != expected {
		return recoveryContractSourceSnapshot{}, errors.Join(errors.New("installed recovery unit source differs from the signed contract"), err)
	}
	var afterFD syscall.Stat_t
	afterInfo, statErr := os.Lstat(path)
	after, afterOK := afterInfo.Sys().(*syscall.Stat_t)
	if fstatErr := syscall.Fstat(int(file.Fd()), &afterFD); fstatErr != nil || statErr != nil || !afterOK ||
		!sameRecoveryContractStat(*before, afterFD) || !sameRecoveryContractStat(*before, *after) {
		return recoveryContractSourceSnapshot{}, errors.Join(errors.New("installed recovery unit source changed during descriptor-bound hashing"), fstatErr, statErr)
	}
	afterAncestors, err := captureRecoverySourceAncestors(path, namespaceRoot, requireProductionAncestors)
	if err != nil || !reflect.DeepEqual(beforeAncestors, afterAncestors) {
		return recoveryContractSourceSnapshot{}, errors.Join(errors.New("installed recovery unit source ancestor changed during descriptor-bound hashing"), err)
	}
	return recoveryContractSourceSnapshot{file: recoveryContractIdentity(*before), ancestors: beforeAncestors}, nil
}

func recoveryPathWithinRoot(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != "." && relative != "" && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func captureRecoverySourceAncestors(path, namespaceRoot string, requireProductionAncestors bool) (map[string]recoveryContractFileIdentity, error) {
	if !cleanAbsolute(path) || !cleanAbsolute(namespaceRoot) || !recoveryPathWithinRoot(path, namespaceRoot) {
		return nil, errors.New("installed recovery unit source ancestor proof is invalid")
	}
	start := namespaceRoot
	if requireProductionAncestors {
		start = string(filepath.Separator)
	}
	parent := filepath.Dir(path)
	relative, err := filepath.Rel(start, parent)
	if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("installed recovery unit source is outside its trusted ancestor namespace")
	}
	directories := []string{start}
	if relative != "." && relative != "" {
		current := start
		for _, component := range strings.Split(relative, string(filepath.Separator)) {
			if component == "" || component == "." || component == ".." {
				return nil, errors.New("installed recovery unit source ancestor is not canonical")
			}
			current = filepath.Join(current, component)
			directories = append(directories, current)
		}
	}
	result := make(map[string]recoveryContractFileIdentity, len(directories))
	for _, directory := range directories {
		info, err := os.Lstat(directory)
		var stat *syscall.Stat_t
		ok := false
		if info != nil {
			stat, ok = info.Sys().(*syscall.Stat_t)
		}
		if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || stat.Uid != 0 || stat.Gid != 0 {
			return nil, errors.Join(fmt.Errorf("installed recovery unit source ancestor %s is unsafe", directory), err)
		}
		result[directory] = recoveryContractIdentity(*stat)
	}
	return result, nil
}

func recoveryContractIdentity(stat syscall.Stat_t) recoveryContractFileIdentity {
	return recoveryContractFileIdentity{
		device: uint64(stat.Dev), inode: stat.Ino, mode: stat.Mode, uid: stat.Uid, gid: stat.Gid,
		links: uint64(stat.Nlink), size: stat.Size,
		mtimeSecond: stat.Mtim.Sec, mtimeNano: stat.Mtim.Nsec,
		ctimeSecond: stat.Ctim.Sec, ctimeNano: stat.Ctim.Nsec,
	}
}

func sameRecoveryContractStat(left, right syscall.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode && left.Uid == right.Uid && left.Gid == right.Gid &&
		left.Nlink == right.Nlink && left.Size == right.Size && left.Mtim == right.Mtim && left.Ctim == right.Ctim
}

func recoveryPayloadSHA256(payload []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(payload))
}

func loadInstalledRecoveryContractCatalog() (config.Portal, []config.Tenant, error) {
	portal, err := config.LoadPortal("/etc/workagent/portal.json")
	if err != nil {
		return config.Portal{}, nil, fmt.Errorf("load installed Portal policy for recovery contract replay: %w", err)
	}
	if err := portal.ValidateProductionLayout("/etc/workagent/portal.json"); err != nil {
		return config.Portal{}, nil, err
	}
	entries, err := os.ReadDir(portal.Paths.TenantConfigs)
	if err != nil {
		return config.Portal{}, nil, fmt.Errorf("enumerate installed tenant catalog for recovery contract replay: %w", err)
	}
	tenants := make([]config.Tenant, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return config.Portal{}, nil, fmt.Errorf("installed recovery tenant catalog contains unexpected entry %q", entry.Name())
		}
		path := filepath.Join(portal.Paths.TenantConfigs, entry.Name())
		tenant, err := config.LoadTenant(path)
		if err != nil || entry.Name() != tenant.TenantID+".json" {
			return config.Portal{}, nil, errors.Join(errors.New("installed recovery tenant catalog is invalid"), err)
		}
		tenants = append(tenants, tenant)
	}
	if len(tenants) == 0 {
		return config.Portal{}, nil, errors.New("installed recovery tenant catalog is empty")
	}
	sort.Slice(tenants, func(i, j int) bool { return tenants[i].TenantID < tenants[j].TenantID })
	return portal, tenants, nil
}

func requireRecoveryRollbackSystemdContract(ctx context.Context, controller systemdctl.Controller, journal recoveryActivationJournal) error {
	if err := validateRecoveryActivationJournal(journal); err != nil {
		return err
	}
	portal, tenants, err := loadInstalledRecoveryContractCatalog()
	if err != nil {
		return err
	}
	contract, err := newProductionRecoverySystemdContract(portal, tenants)
	if err != nil {
		return err
	}
	states := contract.baselineUnitFileStates()
	if err := contract.requireFleet(ctx, controller, states); err != nil {
		return fmt.Errorf("prove exact signed systemd contract after recovery activation rollback: %w", err)
	}
	return nil
}
