//go:build linux

package backup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

type recoveryContractController struct {
	values      map[string]string
	second      map[string]string
	reads       int
	betweenRead func()
}

func (controller *recoveryContractController) Properties(_ context.Context, _ string, _ ...string) (map[string]string, error) {
	controller.reads++
	if controller.reads == 2 && controller.betweenRead != nil {
		controller.betweenRead()
	}
	source := controller.values
	if controller.reads > 1 && controller.second != nil {
		source = controller.second
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result, nil
}

func (*recoveryContractController) Action(context.Context, ...string) error { return nil }

func TestRecoveryUnitCommandParserHandlesPrefixesQuotesResetAndPost(t *testing.T) {
	base := []byte(`[Service]
Type=notify
User=old
Group=old
ExecStartPre=+/usr/libexec/workagent-core-activation-admission-v1
ExecStartPre=+/usr/libexec/workagent-recovery-activation-admission-v1
ExecStart=/bin/bash -c '/usr/bin/flock --shared 3 || exit 70; exec "$@"' workagent-runtime-start /opt/workagent/control/bin/workagent-portal --config /etc/workagent/portal.json
ExecStartPost=/usr/bin/test -r '/path with spaces/value'
ExecStop=/usr/bin/true
ExecStopPost=/usr/bin/test -r '/old stop path'
ExecReload=/usr/bin/test -x /bin/bash
`)
	dropIn := []byte(`[Service]
User=workagent
Group=workagent
ExecStartPre=
ExecStartPre=+/usr/libexec/workagent-core-activation-admission-v1
ExecStartPre=+/usr/libexec/workagent-recovery-activation-admission-v1
ExecStartPre=/usr/bin/test -r /etc/workagent/portal.json
ExecStartPost=
ExecStartPost=/usr/bin/test -r /etc/workagent/portal.json
ExecStopPost=
ExecStopPost=/usr/bin/test -r '/new stop path'
`)
	commands, err := parseRecoveryUnitCommands(base, dropIn)
	if err != nil {
		t.Fatal(err)
	}
	if commands.serviceType != "notify" || commands.user != "workagent" || commands.group != "workagent" {
		t.Fatalf("effective service identity was not parsed: %+v", commands)
	}
	if len(commands.execStart) != 1 || len(commands.execStartPre) != 3 || len(commands.execStartPost) != 1 ||
		len(commands.execStop) != 1 || len(commands.execStopPost) != 1 || len(commands.execReload) != 1 {
		t.Fatalf("effective command lists were not parsed exactly: %+v", commands)
	}
	if !commands.execStartPre[0].privileged || !commands.execStartPre[1].privileged || commands.execStartPre[2].privileged {
		t.Fatal("privileged command prefixes were not retained")
	}
	expectedShell := `/usr/bin/flock --shared 3 || exit 70; exec "$@"`
	if commands.execStart[0].argv[2] != expectedShell {
		t.Fatalf("quoted shell argv = %q, want %q", commands.execStart[0].argv[2], expectedShell)
	}
	if commands.execStartPost[0].argv[2] != "/etc/workagent/portal.json" {
		t.Fatalf("ExecStartPost reset did not replace the base command: %v", commands.execStartPost)
	}
	if commands.execStopPost[0].argv[2] != "/new stop path" {
		t.Fatalf("ExecStopPost reset did not replace the base command: %v", commands.execStopPost)
	}
	if err := validateRecoveryAdmissionCommandOrder("workagent-portal.service", commands.execStartPre, true); err != nil {
		t.Fatalf("exact core/recovery admission prefix was rejected: %v", err)
	}

	bad := append([]recoveryExecCommand(nil), commands.execStartPre...)
	bad[0], bad[1] = bad[1], bad[0]
	if err := validateRecoveryAdmissionCommandOrder("workagent-portal.service", bad, true); err == nil {
		t.Fatal("reversed recovery/core admission order was accepted")
	}
	if _, err := parseRecoveryUnitCommands([]byte("[Service]\nExecStart=/bin/echo 'unterminated\n")); err == nil {
		t.Fatal("unterminated systemd quoting was accepted")
	}
}

func TestRecoveryMountManagerContractIsExact(t *testing.T) {
	payload := []byte(`[Mount]
What=/var/lib/workagent-storage/tenants.xfs
Where=/srv/workagent/users
Type=xfs
Options=loop,prjquota,nodev,nosuid
DirectoryMode=0711
TimeoutSec=90s
`)
	commands, err := parseRecoveryUnitCommands(payload)
	if err != nil {
		t.Fatal(err)
	}
	if commands.mountWhat != "/var/lib/workagent-storage/tenants.xfs" || commands.mountWhere != "/srv/workagent/users" ||
		commands.mountType != "xfs" || commands.mountOptions != "loop,prjquota,nodev,nosuid" {
		t.Fatalf("signed mount semantics were not parsed exactly: %+v", commands)
	}
	spec := recoveryUnitContractSpec{unit: "srv-workagent-users.mount", commands: commands}
	properties := map[string]string{
		"LoadState": "loaded", "UnitFileState": "enabled", "NeedDaemonReload": "no",
		"What": commands.mountWhat, "Where": commands.mountWhere, "Type": commands.mountType, "Options": commands.mountOptions,
	}
	contract := &recoverySystemdContract{}
	if err := contract.validateManagerUnit(spec, properties, "enabled"); err != nil {
		t.Fatalf("exact manager-loaded mount semantics were rejected: %v", err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"What":    func(value map[string]string) { value["What"] = "/tmp/foreign.img" },
		"Where":   func(value map[string]string) { value["Where"] = "/tmp/foreign-mount" },
		"Type":    func(value map[string]string) { value["Type"] = "ext4" },
		"Options": func(value map[string]string) { value["Options"] = "loop,rw,exec,suid" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneRecoveryContractProperties(properties)
			mutate(changed)
			if err := contract.validateManagerUnit(spec, changed, "enabled"); err == nil {
				t.Fatal("drifted manager-loaded mount semantics were accepted")
			}
		})
	}
}

func TestRecoverySocketManagerContractIsExact(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111111"
	payload := []byte(`[Socket]
ListenStream=/run/workagent/users/%i.sock
SocketUser=workagent
SocketGroup=workagent
SocketMode=0600
DirectoryMode=0700
Backlog=64
RemoveOnStop=yes
Service=workagent-userhost@%i.service
`)
	commands, err := parseRecoveryUnitCommands(payload)
	if err != nil {
		t.Fatal(err)
	}
	unit := "workagent-userhost@" + tenantID + ".socket"
	spec := recoveryUnitContractSpec{unit: unit, commands: commands}
	properties := map[string]string{
		"LoadState": "loaded", "UnitFileState": "disabled", "NeedDaemonReload": "no",
		"Listen":        "/run/workagent/users/" + tenantID + ".sock (Stream)",
		"SocketUser":    "workagent",
		"SocketGroup":   "workagent",
		"SocketMode":    "0600",
		"DirectoryMode": "0700",
		"Backlog":       "64",
		"RemoveOnStop":  "yes",
		"Accept":        "no",
		"Triggers":      "workagent-userhost@" + tenantID + ".service",
	}
	contract := &recoverySystemdContract{}
	if err := contract.validateManagerUnit(spec, properties, "disabled"); err != nil {
		t.Fatalf("exact manager-loaded socket semantics were rejected: %v", err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"Listen":        func(value map[string]string) { value["Listen"] = "0.0.0.0:8080 (Stream)" },
		"SocketUser":    func(value map[string]string) { value["SocketUser"] = "root" },
		"SocketGroup":   func(value map[string]string) { value["SocketGroup"] = "root" },
		"SocketMode":    func(value map[string]string) { value["SocketMode"] = "0666" },
		"DirectoryMode": func(value map[string]string) { value["DirectoryMode"] = "0777" },
		"Backlog":       func(value map[string]string) { value["Backlog"] = "1" },
		"RemoveOnStop":  func(value map[string]string) { value["RemoveOnStop"] = "no" },
		"Accept":        func(value map[string]string) { value["Accept"] = "yes" },
		"Triggers":      func(value map[string]string) { value["Triggers"] = "ssh.service" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneRecoveryContractProperties(properties)
			mutate(changed)
			if err := contract.validateManagerUnit(spec, changed, "disabled"); err == nil {
				t.Fatal("drifted manager-loaded socket semantics were accepted")
			}
		})
	}
}

func TestRecoveryDynamicDropInPayloadsAreExact(t *testing.T) {
	credentialTemplate := []byte(`[Service]
LoadCredentialEncrypted=cliproxy-management-key:/etc/credstore.encrypted/workagent/cliproxy-management-key.cred
LoadCredentialEncrypted=chatforward-key:/etc/credstore.encrypted/workagent/chatforward-key.cred
LoadCredentialEncrypted=notifications-key:/etc/credstore.encrypted/workagent/notifications-key.cred
# Optional Windows-parity administrator impersonation credential. The file
# contains an approved Argon2id password hash, never the plaintext password.
# LoadCredentialEncrypted=admin-master-password-hash:/etc/credstore.encrypted/workagent/admin-master-password-hash.cred
`)
	withoutAdministrator, err := recoveryPortalCredentialsPayload(config.Portal{}, credentialTemplate)
	if err != nil || !bytes.Equal(withoutAdministrator, credentialTemplate) {
		t.Fatalf("disabled optional Portal credential changed the signed template: err=%v", err)
	}
	portal := config.Portal{AdminMasterPasswordHashFile: "/run/credentials/workagent-portal.service/admin-master-password-hash"}
	withAdministrator, err := recoveryPortalCredentialsPayload(portal, credentialTemplate)
	if err != nil {
		t.Fatal(err)
	}
	expectedAdministrator := bytes.Replace(credentialTemplate,
		[]byte("# LoadCredentialEncrypted=admin-master-password-hash:"),
		[]byte("LoadCredentialEncrypted=admin-master-password-hash:"), 1)
	if !bytes.Equal(withAdministrator, expectedAdministrator) {
		t.Fatal("enabled optional Portal credential did not produce the one exact permitted substitution")
	}
	if _, err := recoveryPortalCredentialsPayload(portal, bytes.ReplaceAll(credentialTemplate, []byte("# LoadCredentialEncrypted=admin-master-password-hash:"), []byte("LoadCredentialEncrypted=admin-master-password-hash:"))); err == nil {
		t.Fatal("Portal credential template without the exact optional marker was accepted")
	}
	duplicateMarker := append(append([]byte(nil), credentialTemplate...), []byte("# LoadCredentialEncrypted=admin-master-password-hash:/etc/credstore.encrypted/workagent/admin-master-password-hash.cred\n")...)
	if _, err := recoveryPortalCredentialsPayload(portal, duplicateMarker); err == nil {
		t.Fatal("Portal credential template with a duplicate optional marker was accepted")
	}

	tenant := config.Tenant{
		RuntimeUser: "workagent_tenant_one",
		Limits: config.ResourceLimits{
			MemoryBytes: 512 * 1024 * 1024, CPUPercent: 35, ActiveProcesses: 17,
		},
	}
	identity := recoveryTenantIdentityPayload(tenant)
	if expected := []byte("[Service]\nUser=workagent_tenant_one\nGroup=workagent_tenant_one\n"); !bytes.Equal(identity, expected) {
		t.Fatalf("tenant identity drop-in = %q, want %q", identity, expected)
	}
	resources := recoveryTenantResourcesPayload(tenant)
	if expected := []byte("[Service]\nMemoryHigh=536870912\nMemoryMax=536870912\nCPUQuota=35%\nTasksMax=17\n"); !bytes.Equal(resources, expected) {
		t.Fatalf("tenant resource drop-in = %q, want %q", resources, expected)
	}
	for name, payload := range map[string][]byte{
		"Portal credentials": withAdministrator,
		"tenant identity":    identity,
		"tenant resources":   resources,
	} {
		t.Run(name+" digest", func(t *testing.T) {
			drifted := append(append([]byte(nil), payload...), []byte("ExecStart=/tmp/foreign\n")...)
			if recoveryPayloadSHA256(payload) == recoveryPayloadSHA256(drifted) {
				t.Fatal("dynamic drop-in drift did not change its exact digest")
			}
		})
	}
}

func TestRecoveryDynamicDropInSourceAuthenticationRejectsDrift(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership is part of the production source contract")
	}
	root := t.TempDir()
	tenant := config.Tenant{RuntimeUser: "workagent_tenant_one", Limits: config.DefaultResourceLimits()}
	payloads := map[string][]byte{
		"credentials.conf": []byte("[Service]\nLoadCredentialEncrypted=cliproxy-management-key:/etc/credstore.encrypted/workagent/key.cred\n"),
		"identity.conf":    recoveryTenantIdentityPayload(tenant),
		"resources.conf":   recoveryTenantResourcesPayload(tenant),
	}
	for name, payload := range payloads {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, name)
			writeRecoveryContractFixture(t, path, payload, 0o644)
			digest := recoveryPayloadSHA256(payload)
			if err := verifyRecoverySourceDigest(path, digest, 0o644, root, false); err != nil {
				t.Fatalf("exact dynamic drop-in was rejected: %v", err)
			}
			binding := recoveryDropInBinding{filename: name, exactPath: path, expectedDigest: digest}
			if recoveryDropInPathRoot("workagent-portal.service", path, binding, root) != root ||
				recoveryDropInPathRoot("workagent-portal.service", path+".foreign", binding, root) != "" {
				t.Fatal("dynamic drop-in exact path binding was not enforced")
			}
			drifted := append(append([]byte(nil), payload...), []byte("ExecStart=/tmp/foreign\n")...)
			writeRecoveryContractFixture(t, path, drifted, 0o644)
			if err := verifyRecoverySourceDigest(path, digest, 0o644, root, false); err == nil {
				t.Fatal("drifted dynamic drop-in was accepted")
			}
		})
	}
}

func TestRecoveryTrackedUnitAssetsBuildExactCommandContracts(t *testing.T) {
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	portal, err := config.LoadPortal(filepath.Join(repositoryRoot, "config", "portal.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := config.LoadTenant(filepath.Join(repositoryRoot, "config", "tenant.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	references := make(map[string]recoveryProtectedReference, len(recoverySignedUnitAssets)+len(recoverySignedDropInAssets))
	for _, asset := range append(append([]string(nil), recoverySignedUnitAssets...), recoverySignedDropInAssets...) {
		payload, err := os.ReadFile(filepath.Join(repositoryRoot, "deploy", "systemd", filepath.FromSlash(asset)))
		if err != nil {
			t.Fatalf("read tracked unit asset %s: %v", asset, err)
		}
		relative := filepath.ToSlash(filepath.Join(recoveryUnitAssetRoot, asset))
		references[relative] = recoveryProtectedReference{path: filepath.Join(repositoryRoot, "deploy", "systemd", filepath.FromSlash(asset)), digest: recoveryPayloadSHA256(payload), payload: payload}
	}
	credentialTemplate := references[filepath.ToSlash(filepath.Join(recoveryUnitAssetRoot, "workagent-portal.service.d/credentials.conf.example"))].payload
	portalCredentials, err := recoveryPortalCredentialsPayload(portal, credentialTemplate)
	if err != nil {
		t.Fatal(err)
	}
	contract := &recoverySystemdContract{layout: productionRecoverySystemdContractLayout()}
	units := []string{
		"srv-workagent-users.mount", "cliproxyapi.service", "workagent-notification.service",
		"workagent-chatforward.service", "workagent-chatforward-browser.service", "workagent-portal.service",
		"workagent-tenant-catalog-ready.target", "workagent-tenant-config-reconcile.service", "caddy.service",
		"workagent-backup.service", "workagent-backup.timer", "workagent-healthcheck.service", "workagent-healthcheck.timer",
		"workagent-userhost@" + tenant.TenantID + ".service", "workagent-userhost@" + tenant.TenantID + ".socket",
	}
	for _, unit := range units {
		value := config.Tenant{}
		if strings.HasPrefix(unit, "workagent-userhost@") {
			value = tenant
		}
		spec, err := contract.buildUnitSpec(unit, value, references, portalCredentials)
		if err != nil {
			t.Fatalf("tracked effective command contract for %s is invalid: %v", unit, err)
		}
		if unit == "workagent-backup.service" {
			if len(spec.commands.execStopPost) != 1 {
				t.Fatalf("tracked backup service ExecStopPost contract = %v, want exactly one command", spec.commands.execStopPost)
			}
			command := spec.commands.execStopPost[0]
			want := "/usr/bin/flock --exclusive --nonblock --conflict-exit-code 0 /run/workagent/activation.lock /usr/bin/flock --shared /run/workagent/release-config.lock /usr/bin/flock --shared /opt/workagent/control.lock /opt/workagent/control/bin/workagent-backup resume"
			if got := strings.Join(command.argv, " "); got != want || command.privileged || command.ignoreFailure {
				t.Fatalf("tracked backup service ExecStopPost = %q privileged=%t ignoreFailure=%t, want exact nonblocking resume contract", got, command.privileged, command.ignoreFailure)
			}
			regular := recoveryManagerEntry(command, false)
			extended := recoveryManagerEntry(command, true)
			if !matchRecoveryManagerExecSequence(regular, spec.commands.execStopPost, unit, false) ||
				!matchRecoveryManagerExecSequence(extended, spec.commands.execStopPost, unit, true) {
				t.Fatal("tracked backup service ExecStopPost manager forms were rejected")
			}
			for _, drift := range []string{
				strings.Replace(regular, "--nonblock", "--timeout 1", 1),
				strings.Replace(regular, "--conflict-exit-code 0", "--conflict-exit-code 1", 1),
				strings.Replace(extended, "--nonblock", "--timeout 1", 1),
				strings.Replace(extended, "--conflict-exit-code 0", "--conflict-exit-code 1", 1),
			} {
				if matchRecoveryManagerExecSequence(drift, spec.commands.execStopPost, unit, strings.Contains(drift, " flags=")) {
					t.Fatalf("drifted backup ExecStopPost manager command was accepted: %s", drift)
				}
			}
		}
	}
}

func TestRecoverySystemdAnalyzeAcceptsContractSyntax(t *testing.T) {
	analyzer, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze is unavailable")
	}
	unit := []byte(`[Unit]
Description=WorkAgent recovery contract parser fixture

[Service]
Type=oneshot
User=root
Group=root
ExecStartPre=
ExecStartPre=+/usr/bin/true
ExecStart=/usr/bin/true
ExecStartPost=/usr/bin/true
ExecStop=/usr/bin/true
ExecStopPost=/usr/bin/true
ExecReload=/usr/bin/true

[Install]
WantedBy=multi-user.target
`)
	path := filepath.Join(t.TempDir(), "workagent-recovery-contract-parser-fixture.service")
	if err := os.WriteFile(path, unit, 0o644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(analyzer, "--recursive-errors=no", "verify", path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("systemd-analyze rejected recovery command syntax: %v\n%s", err, output)
	}
}

func TestRecoveryManagerCommandSequenceIsExact(t *testing.T) {
	commands := []recoveryExecCommand{
		{argv: []string{"/usr/libexec/workagent-core-activation-admission-v1"}, privileged: true},
		{argv: []string{"/usr/libexec/workagent-recovery-activation-admission-v1"}, privileged: true},
		{argv: []string{"/usr/bin/test", "-r", "/etc/workagent/portal.json"}},
	}
	regular := recoveryManagerEntry(commands[0], false) + " ; " + recoveryManagerEntry(commands[1], false) + " ; " + recoveryManagerEntry(commands[2], false)
	extended := recoveryManagerEntry(commands[0], true) + " ; " + recoveryManagerEntry(commands[1], true) + " ; " + recoveryManagerEntry(commands[2], true)
	if !matchRecoveryManagerExecSequence(regular, commands, "workagent-portal.service", false) {
		t.Fatalf("exact regular manager command sequence was rejected: %s", regular)
	}
	if !matchRecoveryManagerExecSequence(extended, commands, "workagent-portal.service", true) {
		t.Fatalf("exact extended manager command sequence was rejected: %s", extended)
	}
	for name, value := range map[string]string{
		"extra command": regular + " ; " + recoveryManagerEntry(commands[2], false),
		"changed argv":  strings.Replace(regular, "/etc/workagent/portal.json", "/tmp/foreign", 1),
		"changed order": recoveryManagerEntry(commands[1], false) + " ; " + recoveryManagerEntry(commands[0], false) + " ; " + recoveryManagerEntry(commands[2], false),
	} {
		t.Run(name, func(t *testing.T) {
			if matchRecoveryManagerExecSequence(value, commands, "workagent-portal.service", false) {
				t.Fatal("drifted manager command sequence was accepted")
			}
		})
	}
	nonPrivileged := strings.Replace(extended, "flags=privileged ;", "flags= ;", 1)
	if matchRecoveryManagerExecSequence(nonPrivileged, commands, "workagent-portal.service", true) {
		t.Fatal("manager dropped the privileged admission flag without detection")
	}
	for name, drift := range map[string]string{
		"unexpected no-env-expand flag":  strings.Replace(extended, "flags=privileged ;", "flags=privileged no-env-expand ;", 1),
		"unexpected ignore-failure flag": strings.Replace(extended, "flags= ;", "flags=ignore-failure ;", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if matchRecoveryManagerExecSequence(drift, commands, "workagent-portal.service", true) {
				t.Fatal("manager-only extended command flag drift was accepted")
			}
		})
	}
}

func TestRecoveryManagerCommandSequenceRequiresSystemd255ExpandedSpecifiers(t *testing.T) {
	tests := []struct {
		name    string
		unit    string
		command recoveryExecCommand
	}{
		{
			name: "instance",
			unit: "workagent-userhost@11111111-1111-4111-8111-111111111111.service",
			command: recoveryExecCommand{argv: []string{
				"/opt/workagent/control/bin/workagent-admin", "verify-tenant", "--tenant-id", "%i",
			}},
		},
		{
			name: "credential directory",
			unit: "workagent-chatforward.service",
			command: recoveryExecCommand{argv: []string{
				"/usr/libexec/workagent-fixed-root-exec-v1", "chatforward", "/opt/workagent/shared/chatforward/integration/run-server.sh", "%d/chatforward-key",
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expanded := recoveryExecCommand{privileged: test.command.privileged, ignoreFailure: test.command.ignoreFailure}
			for _, argument := range test.command.argv {
				value, err := expandRecoverySystemdSpecifiers(argument, test.unit)
				if err != nil {
					t.Fatal(err)
				}
				expanded.argv = append(expanded.argv, value)
			}
			for _, extended := range []bool{false, true} {
				if !matchRecoveryManagerExecSequence(recoveryManagerEntry(expanded, extended), []recoveryExecCommand{test.command}, test.unit, extended) {
					t.Fatal("systemd 255 expanded manager command was rejected")
				}
				if matchRecoveryManagerExecSequence(recoveryManagerEntry(test.command, extended), []recoveryExecCommand{test.command}, test.unit, extended) {
					t.Fatal("unexpanded unit-file command was accepted as systemd 255 manager memory")
				}
			}
		})
	}
}

func TestRecoveryUnitContractRejectsManagerAndSourceDrift(t *testing.T) {
	root := t.TempDir()
	systemdRoot := filepath.Join(root, "systemd")
	referenceRoot := filepath.Join(root, "control")
	libexecRoot := filepath.Join(root, "libexec")
	for _, path := range []string{systemdRoot, referenceRoot, libexecRoot} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fragmentPayload := []byte("[Service]\nType=simple\nUser=root\nGroup=root\nExecStartPre=+" + filepath.Join(libexecRoot, "admission") + "\nExecStart=/usr/bin/test -r /etc/workagent/portal.json\nExecStop=/usr/bin/test -r /etc/workagent/stop.json\nExecStopPost=/usr/bin/test -r /etc/workagent/stop-post.json\n")
	fragmentPath := filepath.Join(systemdRoot, "test.service")
	referencePath := filepath.Join(referenceRoot, "test.service")
	helperPath := filepath.Join(libexecRoot, "admission")
	helperReferencePath := filepath.Join(referenceRoot, "admission")
	writeRecoveryContractFixture(t, fragmentPath, fragmentPayload, 0o644)
	writeRecoveryContractFixture(t, referencePath, fragmentPayload, 0o444)
	writeRecoveryContractFixture(t, helperPath, []byte("#!/bin/sh\nexit 0\n"), 0o555)
	writeRecoveryContractFixture(t, helperReferencePath, []byte("#!/bin/sh\nexit 0\n"), 0o555)
	fragmentReference, err := loadRecoveryProtectedReference(referencePath)
	if err != nil {
		t.Fatal(err)
	}
	helperReference, err := loadRecoveryProtectedReference(helperReferencePath)
	if err != nil {
		t.Fatal(err)
	}
	pre := recoveryExecCommand{argv: []string{helperPath}, privileged: true}
	start := recoveryExecCommand{argv: []string{"/usr/bin/test", "-r", "/etc/workagent/portal.json"}}
	stop := recoveryExecCommand{argv: []string{"/usr/bin/test", "-r", "/etc/workagent/stop.json"}}
	stopPost := recoveryExecCommand{argv: []string{"/usr/bin/test", "-r", "/etc/workagent/stop-post.json"}}
	spec := recoveryUnitContractSpec{
		unit: "test.service", fragmentAsset: "test.service", fragment: fragmentReference,
		commands: recoveryUnitCommands{
			execStart: []recoveryExecCommand{start}, execStartPre: []recoveryExecCommand{pre},
			execStop: []recoveryExecCommand{stop}, execStopPost: []recoveryExecCommand{stopPost},
			serviceType: "simple", user: "root", group: "root",
		},
	}
	contract := &recoverySystemdContract{
		layout:     recoverySystemdContractLayout{systemdRoots: []string{systemdRoot}, libexecRoot: libexecRoot},
		specs:      map[string]recoveryUnitContractSpec{"test.service": spec},
		helperRefs: map[string]recoveryProtectedReference{helperPath: helperReference},
	}
	properties := map[string]string{
		"LoadState": "loaded", "UnitFileState": "disabled", "FragmentPath": fragmentPath, "DropInPaths": "", "NeedDaemonReload": "no",
		"Type": "simple", "User": "root", "Group": "root",
		"ExecStart": recoveryManagerEntry(start, false), "ExecStartEx": recoveryManagerEntry(start, true),
		"ExecStartPre": recoveryManagerEntry(pre, false), "ExecStartPreEx": recoveryManagerEntry(pre, true),
		"ExecStartPost": "", "ExecStartPostEx": "",
		"ExecStop": recoveryManagerEntry(stop, false), "ExecStopEx": recoveryManagerEntry(stop, true),
		"ExecStopPost": recoveryManagerEntry(stopPost, false), "ExecStopPostEx": recoveryManagerEntry(stopPost, true),
		"ExecReload": "", "ExecReloadEx": "",
	}
	controller := &recoveryContractController{values: properties}
	if err := contract.requireUnit(context.Background(), controller, "test.service", "disabled"); err != nil {
		t.Fatalf("exact manager/source contract was rejected: %v", err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"fragment": func(value map[string]string) { value["FragmentPath"] = filepath.Join(root, "foreign.service") },
		"drop-in": func(value map[string]string) {
			value["DropInPaths"] = filepath.Join(systemdRoot, "test.service.d/foreign.conf")
		},
		"daemon reload":   func(value map[string]string) { value["NeedDaemonReload"] = "yes" },
		"unit file state": func(value map[string]string) { value["UnitFileState"] = "enabled" },
		"exec start": func(value map[string]string) {
			value["ExecStart"] = strings.Replace(value["ExecStart"], "/etc/workagent/portal.json", "/tmp/foreign", 1)
		},
		"exec start ex":  func(value map[string]string) { value["ExecStartEx"] = "" },
		"exec start pre": func(value map[string]string) { value["ExecStartPre"] = "" },
		"exec stop":      func(value map[string]string) { value["ExecStop"] += " ; " + recoveryManagerEntry(stop, false) },
		"exec stop ex":   func(value map[string]string) { value["ExecStopEx"] = "" },
		"exec stop post": func(value map[string]string) {
			value["ExecStopPost"] = strings.Replace(value["ExecStopPost"], "stop-post.json", "foreign.json", 1)
		},
		"exec stop post ex": func(value map[string]string) { value["ExecStopPostEx"] = "" },
		"exec reload ex":    func(value map[string]string) { value["ExecReloadEx"] = recoveryManagerEntry(start, true) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneRecoveryContractProperties(properties)
			mutate(changed)
			controller := &recoveryContractController{values: changed}
			if err := contract.requireUnit(context.Background(), controller, "test.service", "disabled"); err == nil {
				t.Fatal("drifted recovery manager contract was accepted")
			}
		})
	}

	t.Run("manager TOCTOU", func(t *testing.T) {
		second := cloneRecoveryContractProperties(properties)
		second["NeedDaemonReload"] = "yes"
		controller := &recoveryContractController{values: properties, second: second}
		if err := contract.requireUnit(context.Background(), controller, "test.service", "disabled"); err == nil {
			t.Fatal("manager contract mutation between source-bound reads was accepted")
		}
	})

	t.Run("identical leaf replacement between reads", func(t *testing.T) {
		var mutationErr error
		controller := &recoveryContractController{values: properties, betweenRead: func() {
			stage := filepath.Join(systemdRoot, ".replacement.service")
			if err := os.WriteFile(stage, fragmentPayload, 0o644); err != nil {
				mutationErr = err
				return
			}
			if err := os.Chmod(stage, 0o644); err != nil {
				mutationErr = err
				return
			}
			mutationErr = os.Rename(stage, fragmentPath)
		}}
		err := contract.requireUnit(context.Background(), controller, "test.service", "disabled")
		if mutationErr != nil {
			t.Fatal(mutationErr)
		}
		if err == nil {
			t.Fatal("same-byte fragment inode replacement between manager reads was accepted")
		}
	})

	t.Run("identical parent replacement between reads", func(t *testing.T) {
		oldRoot := systemdRoot + ".old"
		var mutationErr error
		controller := &recoveryContractController{values: properties, betweenRead: func() {
			if err := os.Rename(systemdRoot, oldRoot); err != nil {
				mutationErr = err
				return
			}
			if err := os.Mkdir(systemdRoot, 0o755); err != nil {
				mutationErr = err
				return
			}
			mutationErr = os.WriteFile(fragmentPath, fragmentPayload, 0o644)
		}}
		err := contract.requireUnit(context.Background(), controller, "test.service", "disabled")
		if mutationErr != nil {
			t.Fatal(mutationErr)
		}
		if removeErr := os.RemoveAll(systemdRoot); removeErr != nil {
			t.Fatal(removeErr)
		}
		if renameErr := os.Rename(oldRoot, systemdRoot); renameErr != nil {
			t.Fatal(renameErr)
		}
		if err == nil {
			t.Fatal("same-byte systemd parent replacement between manager reads was accepted")
		}
	})

	t.Run("linked parent", func(t *testing.T) {
		oldRoot := systemdRoot + ".real"
		if err := os.Rename(systemdRoot, oldRoot); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(oldRoot, systemdRoot); err != nil {
			t.Fatal(err)
		}
		controller := &recoveryContractController{values: properties}
		err := contract.requireUnit(context.Background(), controller, "test.service", "disabled")
		if removeErr := os.Remove(systemdRoot); removeErr != nil {
			t.Fatal(removeErr)
		}
		if renameErr := os.Rename(oldRoot, systemdRoot); renameErr != nil {
			t.Fatal(renameErr)
		}
		if err == nil {
			t.Fatal("systemd source through a linked parent was accepted")
		}
	})

	t.Run("source replacement", func(t *testing.T) {
		if err := os.WriteFile(fragmentPath, []byte("foreign\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(fragmentPath, 0o644); err != nil {
			t.Fatal(err)
		}
		controller := &recoveryContractController{values: properties}
		if err := contract.requireUnit(context.Background(), controller, "test.service", "disabled"); err == nil {
			t.Fatal("installed fragment content drift was accepted")
		}
	})
}

func TestRecoveryRollbackRetainsJournalOnExactContractProofFailure(t *testing.T) {
	value := recoveryActivationJournal{SchemaVersion: 1, Units: []string{
		"workagent-tenant-catalog-ready.target",
		"cliproxyapi.service",
		"workagent-notification.service",
		"workagent-chatforward.service",
		"workagent-chatforward-browser.service",
		"workagent-portal.service",
	}}
	values := make(map[string]map[string]string, len(value.Units))
	for _, unit := range value.Units {
		values[unit] = stoppedRecoveryProperties()
	}
	values["workagent-tenant-config-reconcile.service"] = stoppedRecoveryProperties()
	values["workagent-tenant-config-reconcile.service"]["UnitFileState"] = "static"
	values["workagent-tenant-catalog-ready.target"]["UnitFileState"] = "static"
	controller := &recordingRecoveryController{values: values}
	loaded, removed, proved := false, false, false
	err := rollbackKnownRecoveryActivationWithIOAndProof(
		controller, value, recoveryActivationJournalPath,
		func(string) (recoveryActivationJournal, bool, error) {
			loaded = true
			return value, true, nil
		},
		func(string) error {
			removed = true
			return nil
		},
		func(context.Context, systemdctl.Controller, recoveryActivationJournal) error {
			proved = true
			return errors.New("manager contract drift")
		},
	)
	if err == nil || !proved || loaded || removed {
		t.Fatalf("contract-proof failure did not retain crash journal: err=%v proved=%t loaded=%t removed=%t", err, proved, loaded, removed)
	}
}

func recoveryManagerEntry(command recoveryExecCommand, extended bool) string {
	base := "{ path=" + command.argv[0] + " ; argv[]=" + strings.Join(command.argv, " ") + " ;"
	if extended {
		var flags []string
		if command.ignoreFailure {
			flags = append(flags, "ignore-failure")
		}
		if command.privileged {
			flags = append(flags, "privileged")
		}
		return base + " flags=" + strings.Join(flags, " ") + " ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
	}
	ignore := "no"
	if command.ignoreFailure {
		ignore = "yes"
	}
	return base + " ignore_errors=" + ignore + " ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
}

func writeRecoveryContractFixture(t *testing.T, path string, payload []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, payload, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func cloneRecoveryContractProperties(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
