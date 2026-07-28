package admin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

type ServiceVerificationOptions struct {
	SystemdRoot        string
	RequireReadySocket bool
	Controller         systemdctl.Controller
}

func VerifyPortalService(ctx context.Context, portal config.Portal, controller systemdctl.Controller) error {
	if err := portal.ValidateProductionLayout("/etc/workagent/portal.json"); err != nil {
		return err
	}
	if controller == nil {
		value := systemdctl.Default()
		controller = value
	}
	identity, err := controller.Properties(ctx, "workagent-portal.service", "LoadState", "User", "Group", "SupplementaryGroups", "MemoryHigh", "MemoryMax", "CPUQuotaPerSecUSec", "TasksMax")
	if err != nil {
		return fmt.Errorf("inspect Portal service identity and limits: %w", err)
	}
	if identity["LoadState"] != "loaded" || identity["User"] != portal.RuntimeUser || identity["Group"] != portal.RuntimeUser || !sameWords(identity["SupplementaryGroups"], nil) {
		return errors.New("Portal service identity does not match policy")
	}
	memoryHigh, highErr := strconv.ParseUint(identity["MemoryHigh"], 10, 64)
	memoryMax, maxErr := strconv.ParseUint(identity["MemoryMax"], 10, 64)
	tasksMax, tasksErr := strconv.ParseUint(identity["TasksMax"], 10, 32)
	cpuQuota, cpuErr := time.ParseDuration(identity["CPUQuotaPerSecUSec"])
	if highErr != nil || maxErr != nil || tasksErr != nil || cpuErr != nil || memoryHigh != 1536*1024*1024 || memoryMax != 2*1024*1024*1024 || tasksMax != 512 || cpuQuota != 2*time.Second {
		return errors.New("Portal service resource limits do not match policy")
	}
	hardening, err := controller.Properties(ctx, "workagent-portal.service",
		"NoNewPrivileges", "UMask", "KillMode", "PrivateDevices", "PrivateTmp", "ProtectClock", "ProtectControlGroups", "ProtectHome", "ProtectHostname",
		"ProtectKernelLogs", "ProtectKernelModules", "ProtectKernelTunables", "ProtectSystem", "RestrictRealtime", "LockPersonality",
		"CapabilityBoundingSet", "AmbientCapabilities", "RestrictAddressFamilies", "SystemCallArchitectures", "ReadWritePaths", "InaccessiblePaths",
		"RestrictNamespaces", "MemoryDenyWriteExecute")
	if err != nil {
		return fmt.Errorf("inspect Portal service sandbox: %w", err)
	}
	for property, expected := range map[string]string{
		"NoNewPrivileges": "yes", "UMask": "0077", "KillMode": "control-group", "PrivateDevices": "yes", "PrivateTmp": "yes", "ProtectClock": "yes",
		"ProtectControlGroups": "yes", "ProtectHome": "yes", "ProtectHostname": "yes", "ProtectKernelLogs": "yes", "ProtectKernelModules": "yes",
		"ProtectKernelTunables": "yes", "ProtectSystem": "strict", "RestrictRealtime": "yes",
		"LockPersonality": "yes", "CapabilityBoundingSet": "", "AmbientCapabilities": "", "SystemCallArchitectures": "native",
		"RestrictNamespaces": "yes", "MemoryDenyWriteExecute": "yes",
	} {
		if hardening[property] != expected {
			return fmt.Errorf("Portal service hardening property %s does not match policy", property)
		}
	}
	if !sameWords(hardening["RestrictAddressFamilies"], []string{"AF_UNIX", "AF_INET", "AF_INET6"}) ||
		!sameWords(hardening["ReadWritePaths"], []string{portal.Paths.PortalState, "/run/workagent"}) ||
		!sameWords(hardening["InaccessiblePaths"], []string{"-" + portal.Paths.TenantData}) {
		return errors.New("Portal service network or filesystem sandbox does not match policy")
	}
	return nil
}

func VerifyTenantService(ctx context.Context, portal config.Portal, tenant config.Tenant, options ServiceVerificationOptions) error {
	if err := ValidateTenantBinding(portal, tenant); err != nil {
		return err
	}
	root := options.SystemdRoot
	if root == "" {
		root = "/etc/systemd/system"
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("systemd root is not canonical")
	}
	identityPath := filepath.Join(root, "workagent-userhost@"+tenant.TenantID+".service.d", "identity.conf")
	info, err := os.Lstat(identityPath)
	if err != nil {
		return fmt.Errorf("inspect tenant systemd identity: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 || info.Size() > 4096 {
		return errors.New("tenant systemd identity drop-in is unsafe")
	}
	payload, err := os.ReadFile(identityPath)
	if err != nil || string(payload) != "[Service]\nUser="+tenant.RuntimeUser+"\nGroup="+tenant.RuntimeUser+"\n" {
		return errors.New("tenant systemd identity drop-in does not match the runtime account")
	}
	limits := tenant.Limits.Effective()
	resourcePath := filepath.Join(filepath.Dir(identityPath), "resources.conf")
	resourceInfo, err := os.Lstat(resourcePath)
	if err != nil {
		return fmt.Errorf("inspect tenant resource limits: %w", err)
	}
	resourceStat, ok := resourceInfo.Sys().(*syscall.Stat_t)
	if !ok || resourceStat.Uid != 0 || resourceStat.Gid != 0 || resourceInfo.Mode()&os.ModeSymlink != 0 || !resourceInfo.Mode().IsRegular() || resourceInfo.Mode().Perm() != 0o644 || resourceInfo.Size() > 4096 {
		return errors.New("tenant resource-limit drop-in is unsafe")
	}
	resourcePayload, err := os.ReadFile(resourcePath)
	if err != nil || string(resourcePayload) != string(ResourceDropInPayload(limits)) {
		return errors.New("tenant resource-limit drop-in does not match tenant configuration")
	}
	controller := options.Controller
	if controller == nil {
		value := systemdctl.Default()
		controller = value
	}
	serviceUnit := "workagent-userhost@" + tenant.TenantID + ".service"
	serviceSource, err := controller.Properties(ctx, serviceUnit, "FragmentPath", "DropInPaths")
	if err != nil {
		return fmt.Errorf("inspect tenant service unit source: %w", err)
	}
	expectedServiceFragment := filepath.Join(root, tenantDropInPrefix+".service")
	expectedServiceDropIns := []string{identityPath, resourcePath}
	if serviceSource["FragmentPath"] != expectedServiceFragment || !sameWords(serviceSource["DropInPaths"], expectedServiceDropIns) {
		return errors.New("tenant service fragment or drop-in source does not match the authenticated systemd namespace")
	}
	service, err := controller.Properties(ctx, serviceUnit,
		"LoadState", "User", "Group", "SupplementaryGroups", "NoNewPrivileges", "MemoryHigh", "MemoryMax", "CPUQuotaPerSecUSec", "TasksMax",
		"UMask", "KillMode", "PrivateDevices", "PrivateTmp", "ProtectClock", "ProtectControlGroups", "ProtectHome", "ProtectHostname", "ProtectKernelLogs",
		"ProtectKernelModules", "ProtectKernelTunables", "ProtectProc", "ProcSubset", "ProtectSystem", "RestrictRealtime", "LockPersonality",
		"CapabilityBoundingSet", "AmbientCapabilities", "RestrictAddressFamilies", "SystemCallArchitectures", "ReadWritePaths", "KeyringMode", "LimitCORE")
	if err != nil {
		return fmt.Errorf("inspect tenant service unit: %w", err)
	}
	if service["LoadState"] != "loaded" || service["User"] != tenant.RuntimeUser || service["Group"] != tenant.RuntimeUser || !sameWords(service["SupplementaryGroups"], []string{"workagent-slots"}) || service["NoNewPrivileges"] != "yes" {
		return errors.New("tenant service identity or hardening properties are incorrect")
	}
	if err := validateTenantSecretIsolation(service); err != nil {
		return err
	}
	for property, expected := range map[string]string{
		"UMask": "0077", "KillMode": "control-group", "PrivateDevices": "yes", "PrivateTmp": "yes", "ProtectClock": "yes", "ProtectControlGroups": "yes",
		"ProtectHome": "yes", "ProtectHostname": "yes", "ProtectKernelLogs": "yes", "ProtectKernelModules": "yes", "ProtectKernelTunables": "yes",
		"ProtectProc": "invisible", "ProcSubset": "pid", "ProtectSystem": "strict", "RestrictRealtime": "yes", "LockPersonality": "yes",
		"CapabilityBoundingSet": "", "AmbientCapabilities": "", "SystemCallArchitectures": "native", "KeyringMode": "private", "LimitCORE": "0",
	} {
		if service[property] != expected {
			return fmt.Errorf("tenant service hardening property %s does not match policy", property)
		}
	}
	if !sameWords(service["RestrictAddressFamilies"], []string{"AF_UNIX", "AF_INET", "AF_INET6"}) || !sameWords(service["ReadWritePaths"], []string{tenant.DataRoot, portal.Paths.RuntimeSockets, tenant.Capacity.SlotDirectory}) {
		return errors.New("tenant service address-family or writable-path sandbox does not match policy")
	}
	memoryHigh, highErr := strconv.ParseUint(service["MemoryHigh"], 10, 64)
	memoryMax, maxErr := strconv.ParseUint(service["MemoryMax"], 10, 64)
	tasksMax, tasksErr := strconv.ParseUint(service["TasksMax"], 10, 32)
	cpuQuota, cpuErr := time.ParseDuration(service["CPUQuotaPerSecUSec"])
	expectedCPUQuota := time.Duration(limits.CPUPercent) * time.Second / 100
	if highErr != nil || maxErr != nil || tasksErr != nil || cpuErr != nil || memoryHigh != limits.MemoryBytes || memoryMax != limits.MemoryBytes || tasksMax != uint64(limits.ActiveProcesses) || cpuQuota != expectedCPUQuota {
		return errors.New("tenant service resource limits do not match tenant configuration")
	}
	socketUnit := "workagent-userhost@" + tenant.TenantID + ".socket"
	socket, err := controller.Properties(ctx, socketUnit, "LoadState", "ActiveState", "UnitFileState", "FragmentPath", "DropInPaths", "Listen", "SocketUser", "SocketGroup", "SocketMode", "DirectoryMode")
	if err != nil {
		return fmt.Errorf("inspect tenant socket unit source and configuration: %w", err)
	}
	expectedSocketFragment := filepath.Join(root, tenantDropInPrefix+".socket")
	if socket["LoadState"] != "loaded" || socket["FragmentPath"] != expectedSocketFragment || !sameWords(socket["DropInPaths"], nil) ||
		!exactTenantSocketListen(socket["Listen"], tenant.SocketPath) || socket["SocketUser"] != portal.RuntimeUser || socket["SocketGroup"] != portal.RuntimeUser ||
		socket["SocketMode"] != "0600" || socket["DirectoryMode"] != "0700" {
		return errors.New("tenant socket fragment, drop-ins, or static configuration do not match policy")
	}
	if !options.RequireReadySocket {
		return nil
	}
	if socket["ActiveState"] != "active" || (socket["UnitFileState"] != "enabled" && socket["UnitFileState"] != "enabled-runtime") {
		return errors.New("tenant socket unit is not enabled with the required ownership and mode")
	}
	socketInfo, err := os.Lstat(tenant.SocketPath)
	if err != nil {
		return fmt.Errorf("inspect active tenant socket: %w", err)
	}
	portalAccount, err := user.Lookup(portal.RuntimeUser)
	if err != nil {
		return fmt.Errorf("lookup Portal account for active socket: %w", err)
	}
	portalGID, err := parseUID(portalAccount.Gid)
	if err != nil {
		return errors.New("Portal group is invalid")
	}
	socketStat, ok := socketInfo.Sys().(*syscall.Stat_t)
	if !ok || socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode().Perm() != 0o600 || socketStat.Uid != tenant.PortalUID || socketStat.Gid != portalGID {
		return errors.New("active tenant socket has incorrect type, owner, or mode")
	}
	return nil
}

func exactTenantSocketListen(value, socketPath string) bool {
	return value == socketPath || value == socketPath+" (Stream)"
}

func validateTenantSecretIsolation(properties map[string]string) error {
	if properties["KeyringMode"] != "private" || properties["LimitCORE"] != "0" {
		return errors.New("tenant service keyring or core-dump policy does not match policy")
	}
	return nil
}

func sameWords(value string, expected []string) bool {
	actual := strings.Fields(value)
	if len(actual) != len(expected) {
		return false
	}
	wanted := make(map[string]bool, len(expected))
	for _, word := range expected {
		if word == "" || wanted[word] {
			return false
		}
		wanted[word] = true
	}
	for _, word := range actual {
		if !wanted[word] {
			return false
		}
		delete(wanted, word)
	}
	return len(wanted) == 0
}
