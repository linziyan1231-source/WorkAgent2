//go:build linux

package serviceaction

import (
	"maps"
	"strings"
	"testing"
)

func TestCoreManagerExecVectorsRejectTransientEffectiveCommandTampering(t *testing.T) {
	plainRecord := func(executable, arguments string) string {
		return "{ path=" + executable + " ; argv[]=" + arguments + " ; ignore_errors=no ; pid=0 ; code=(null) ; status=0/0 }"
	}
	extendedRecord := func(executable, arguments string, privileged bool) string {
		flags := ""
		if privileged {
			flags = "privileged"
		}
		return "{ path=" + executable + " ; argv[]=" + arguments + " ; flags=" + flags + " ; pid=0 ; code=(null) ; status=0/0 }"
	}
	join := func(records ...string) string { return strings.Join(records, " ; ") }
	core := "/usr/libexec/workagent-core-activation-admission-v1"
	recovery := "/usr/libexec/workagent-recovery-activation-admission-v1"
	verify := "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-release verify --root /opt/workagent/control --scope portal --required-executable bin/workagent-notification --required-executable bin/workagent-release"
	testRead := "/usr/bin/test -r /etc/workagent/notification.json"
	ready := "/usr/bin/curl --noproxy * --fail --silent --show-error --retry 10 --retry-delay 1 --retry-connrefused --max-time 15 http://127.0.0.1:25888/readyz"
	properties := map[string]string{
		"ExecStartPre":    join(plainRecord(core, core), plainRecord(recovery, recovery), plainRecord("/usr/bin/flock", verify), plainRecord("/usr/bin/test", testRead)),
		"ExecStartPreEx":  join(extendedRecord(core, core, true), extendedRecord(recovery, recovery, true), extendedRecord("/usr/bin/flock", verify, true), extendedRecord("/usr/bin/test", testRead, false)),
		"ExecStartPost":   plainRecord("/usr/bin/curl", ready),
		"ExecStartPostEx": extendedRecord("/usr/bin/curl", ready, false),
		"ExecStopPost":    "", "ExecStopPostEx": "", "ExecReload": "",
	}
	if !verifyCoreServiceExecVectors("workagent-notification.service", properties) {
		t.Fatal("exact notification effective command vectors were rejected")
	}
	for _, field := range []string{"ExecStartPre", "ExecStartPreEx", "ExecStartPost", "ExecStartPostEx", "ExecReload", "ExecReloadEx"} {
		t.Run(field, func(t *testing.T) {
			tampered := maps.Clone(properties)
			if field == "ExecReload" {
				tampered[field] = plainRecord("/bin/true", "/bin/true")
			} else {
				tampered[field] += " drift"
			}
			if verifyCoreServiceExecVectors("workagent-notification.service", tampered) {
				t.Fatalf("transient manager tampering of %s was accepted", field)
			}
		})
	}
	manager := maps.Clone(properties)
	manager["LoadState"], manager["NeedDaemonReload"], manager["FragmentPath"], manager["UnitFileState"] = "loaded", "no", "/usr/lib/systemd/system/workagent-notification.service", "enabled"
	manager["Type"], manager["User"], manager["Group"] = "simple", "workagent-notification", "workagent-notification"
	start := "/usr/libexec/workagent-fixed-root-exec-v1 notification /opt/workagent/control/bin/workagent-notification"
	manager["ExecStart"] = plainRecord("/usr/libexec/workagent-fixed-root-exec-v1", start)
	manager["ExecStartEx"] = extendedRecord("/usr/libexec/workagent-fixed-root-exec-v1", start, false)
	manager["ExecStop"], manager["ExecStopEx"] = "", ""
	if err := VerifyCoreManagerContract("workagent-notification.service", manager); err != nil {
		t.Fatalf("exact notification manager contract was rejected: %v", err)
	}
	for _, field := range []string{"ExecStartEx", "ExecStop", "ExecStopEx"} {
		t.Run(field, func(t *testing.T) {
			tampered := maps.Clone(manager)
			tampered[field] = extendedRecord("/bin/true", "/bin/true", field == "ExecStartEx")
			if err := VerifyCoreManagerContract("workagent-notification.service", tampered); err == nil {
				t.Fatalf("transient manager tampering of %s was accepted", field)
			}
		})
	}

	backupProperties := map[string]string{
		"ExecStartPre": join(
			plainRecord(core, core),
			plainRecord("/usr/bin/flock", "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-release verify --root /opt/workagent/control --scope portal --required-executable bin/workagent-backup --required-executable bin/workagent-release")),
		"ExecStartPreEx": join(
			extendedRecord(core, core, true),
			extendedRecord("/usr/bin/flock", "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-release verify --root /opt/workagent/control --scope portal --required-executable bin/workagent-backup --required-executable bin/workagent-release", true)),
		"ExecStartPost": "", "ExecStartPostEx": "", "ExecReload": "",
	}
	stopPost := "/usr/bin/flock --exclusive --nonblock --conflict-exit-code 0 /run/workagent/activation.lock /usr/bin/flock --shared /run/workagent/release-config.lock /usr/bin/flock --shared /opt/workagent/control.lock /opt/workagent/control/bin/workagent-backup resume"
	backupProperties["ExecStopPost"] = plainRecord("/usr/bin/flock", stopPost)
	backupProperties["ExecStopPostEx"] = extendedRecord("/usr/bin/flock", stopPost, false)
	if !verifyCoreServiceExecVectors("workagent-backup.service", backupProperties) {
		t.Fatal("exact backup stop-post vector was rejected")
	}
	backupProperties["ExecStopPost"] = strings.Replace(backupProperties["ExecStopPost"], "--nonblock", "--wait", 1)
	if verifyCoreServiceExecVectors("workagent-backup.service", backupProperties) {
		t.Fatal("tampered backup stop-post vector was accepted")
	}
}

func TestCoreCaddyManagerContractRejectsNonPersistentUnitState(t *testing.T) {
	for _, invalid := range []string{"static", "masked", "linked", "bad"} {
		t.Run(invalid, func(t *testing.T) {
			properties := caddyServiceState(false, false, "", 0)
			properties["UnitFileState"] = invalid
			if err := VerifyCoreManagerContract("caddy.service", properties); err == nil {
				t.Fatalf("Caddy UnitFileState=%s was accepted by the core contract", invalid)
			}
		})
	}
}

func TestChatForwardManagerContractAcceptsOnlyExpandedCredentialSpecifier(t *testing.T) {
	plain := func(arguments string) string {
		return "{ path=/usr/libexec/workagent-fixed-root-exec-v1 ; argv[]=" + arguments + " ; ignore_errors=no ; pid=0 ; code=(null) ; status=0/0 }"
	}
	extended := func(arguments string) string {
		return "{ path=/usr/libexec/workagent-fixed-root-exec-v1 ; argv[]=" + arguments + " ; flags= ; pid=0 ; code=(null) ; status=0/0 }"
	}
	expected := []systemdExecContract{{executable: "/usr/libexec/workagent-fixed-root-exec-v1", flattenedArgv: coreChatForwardManagerExec}}
	if !exactCoreManagerExecVector(plain(coreChatForwardManagerExec), extended(coreChatForwardManagerExec), expected) {
		t.Fatal("expanded systemd credential directory was rejected")
	}
	raw := strings.Replace(coreChatForwardManagerExec, "/run/credentials/workagent-chatforward.service", "%d", 1)
	if exactCoreManagerExecVector(plain(raw), extended(raw), expected) {
		t.Fatal("unexpanded percent-d credential specifier was accepted from manager state")
	}
}
