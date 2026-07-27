package deployassets

import (
	"strings"
	"testing"
)

func TestFixedRootServiceConsumersUseVersionedLifecycleSupervisor(t *testing.T) {
	contracts := []struct {
		path        string
		profile     string
		usesShared  bool
		mainCommand string
	}{
		{"deploy/systemd/workagent-backup.service", "backup", false, "/opt/workagent/control/bin/workagent-backup create --portal-config /etc/workagent/portal.json --config /etc/workagent/backup.json --quiesce-systemd"},
		{"deploy/systemd/workagent-healthcheck.service", "healthcheck", false, "/opt/workagent/control/bin/workagent-healthcheck /var/lib/node_exporter/textfile_collector/workagent_host.prom"},
		{"deploy/systemd/workagent-notification.service", "notification", false, "/opt/workagent/control/bin/workagent-notification"},
		{"deploy/systemd/cliproxyapi.service", "cliproxyapi", true, "/opt/workagent/shared/cliproxyapi/bin/cli-proxy-api --config /var/lib/cliproxyapi/config.yaml"},
		{"deploy/systemd/workagent-chatforward.service", "chatforward", true, "/opt/workagent/shared/chatforward/integration/run-server.sh %d/chatforward-key"},
		{"deploy/systemd/workagent-chatforward-browser.service", "chatforward-browser", true, "/opt/workagent/shared/chatforward/integration/run-browser.sh"},
	}

	for _, contract := range contracts {
		t.Run(contract.path, func(t *testing.T) {
			unit := repositoryFile(t, contract.path)
			catalogOpen := "OpenFile=/run/workagent/release-config.lock:workagent-config-lock:read-only"
			controlOpen := "OpenFile=/opt/workagent/control.lock:workagent-control-release-lock:read-only"
			requireContains(t, unit,
				"ConditionFileIsExecutable=/usr/libexec/workagent-fixed-root-exec-v1",
				"ConditionPathExists=/run/workagent/release-config.lock",
				"ConditionPathExists=/opt/workagent/control.lock",
				catalogOpen,
				controlOpen,
			)
			if strings.Index(unit, catalogOpen) >= strings.Index(unit, controlOpen) {
				t.Fatal("catalog OpenFile must precede the control-channel OpenFile")
			}

			if contract.usesShared {
				sharedOpen := "OpenFile=/opt/workagent/shared.lock:workagent-shared-release-lock:read-only"
				requireContains(t, unit,
					"ConditionPathExists=/opt/workagent/shared.lock",
					sharedOpen,
				)
				if strings.Index(unit, controlOpen) >= strings.Index(unit, sharedOpen) {
					t.Fatal("control-channel OpenFile must precede the shared-channel OpenFile")
				}
			}

			preCount := 0
			var preStarts []string
			main := ""
			for _, line := range strings.Split(unit, "\n") {
				switch {
				case strings.HasPrefix(line, "ExecStartPre="):
					preCount++
					preStarts = append(preStarts, line)
					if line == coreAdmissionExecStartPre || line == recoveryAdmissionExecStartPre {
						continue
					}
					if contract.profile == "notification" && line == "ExecStartPre=/usr/bin/test -r /etc/workagent/notification.json" {
						continue
					}
					if !strings.Contains(line, "/usr/bin/flock --shared /run/workagent/release-config.lock ") {
						t.Fatalf("pre-start command does not use a retaining path-form catalog supervisor: %s", line)
					}
					if strings.Contains(line, "/usr/bin/flock --shared --no-fork ") {
						t.Fatalf("pre-start guard delegates lock lifetime to the verifier: %s", line)
					}
				case strings.HasPrefix(line, "ExecStart="):
					main = line
				}
			}
			if preCount == 0 {
				t.Fatal("unit has no guarded pre-start verification")
			}
			if len(preStarts) == 0 || preStarts[0] != coreAdmissionExecStartPre {
				t.Fatalf("first pre-start command = %q, want exact core activation admission", preStarts)
			}
			if strings.Contains(unit, recoveryAdmissionExecStartPre) && (len(preStarts) < 2 || preStarts[1] != recoveryAdmissionExecStartPre) {
				t.Fatalf("recovery admission does not immediately follow core admission: %q", preStarts)
			}
			expectedMain := "ExecStart=/usr/libexec/workagent-fixed-root-exec-v1 " + contract.profile + " " + contract.mainCommand
			if contract.profile == "backup" {
				expectedMain = "ExecStart=/usr/bin/flock --exclusive --no-fork /run/workagent/activation.lock /usr/libexec/workagent-fixed-root-exec-v1 backup " + contract.mainCommand
			}
			if main != expectedMain {
				t.Fatalf("unexpected fixed-root supervisor invocation:\n got %s\nwant %s", main, expectedMain)
			}
			if strings.Contains(unit, "WorkingDirectory=/opt/workagent/") {
				t.Fatal("systemd resolves a mutable fixed-root working directory before the main lock guard")
			}
			if strings.Contains(unit, "/usr/libexec/workagent-fixed-root-exec ") {
				t.Fatal("unit invokes an unversioned mutable lifecycle helper")
			}
		})
	}

	cliproxy := repositoryFile(t, "deploy/systemd/cliproxyapi.service")
	sharedOpen := "OpenFile=/opt/workagent/shared.lock:workagent-shared-release-lock:read-only"
	migrationOpen := "OpenFile=/run/workagent/cliproxy-migration.lock:workagent-cliproxy-migration-lock:read-only"
	requireContains(t, cliproxy,
		migrationOpen,
		"ExecStartPost=+/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-cliproxy bootstrap --portal-config /etc/workagent/portal.json --credential /run/credentials/cliproxyapi.service/cliproxy-management-key --wait 30s",
	)
	if strings.Index(cliproxy, sharedOpen) >= strings.Index(cliproxy, migrationOpen) {
		t.Fatal("CLIProxy migration OpenFile must follow catalog/control/shared at fd 6")
	}

	backup := repositoryFile(t, "deploy/systemd/workagent-backup.service")
	requireContains(t, backup,
		"ExecStart=/usr/bin/flock --exclusive --no-fork /run/workagent/activation.lock /usr/libexec/workagent-fixed-root-exec-v1 backup /opt/workagent/control/bin/workagent-backup create --portal-config /etc/workagent/portal.json --config /etc/workagent/backup.json --quiesce-systemd",
		"ExecStopPost=/usr/bin/flock --exclusive --nonblock --conflict-exit-code 0 /run/workagent/activation.lock /usr/bin/flock --shared /run/workagent/release-config.lock /usr/bin/flock --shared /opt/workagent/control.lock /opt/workagent/control/bin/workagent-backup resume",
	)
}

func TestFixedRootLifecycleSupervisorV1IsClosedAndRetaining(t *testing.T) {
	requireRepositoryExecutable(t, "deploy/libexec/workagent-fixed-root-exec-v1")
	helper := repositoryFile(t, "deploy/libexec/workagent-fixed-root-exec-v1")
	requireContains(t, helper,
		"#!/bin/bash\n",
		"export LC_ALL=C",
		"export PATH=/usr/bin:/bin",
		`expected_names=$catalog_name:$control_name`,
		`expected_names=$catalog_name:$control_name:$shared_name`,
		`expected_names=$catalog_name:$control_name:$shared_name:$cliproxy_migration_name`,
		`expected_names=$catalog_name:$control_name:$shared_name:$cliproxy_migration_name:$cliproxy_oauth_name`,
		`expected_names=$activation_name:$catalog_name:$control_name:$shared_name`,
		`migration_shape=0:$group_gid:640:1:0`,
		`oauth_shape=$migration_shape`,
		`expected_shapes=(0:0:600:1:0 0:0:600:1:0 0:0:600:1:0 "$migration_shape")`,
		`expected_shapes=(0:0:600:1:0 0:0:600:1:0 0:0:600:1:0 "$migration_shape" "$oauth_shape")`,
		`if [[ ${LISTEN_PID:-} != "$$" || ${LISTEN_FDS:-} != "$expected_count" || ${LISTEN_FDNAMES:-} != "$expected_names" ]]`,
		`/usr/bin/flock --exclusive "$activation_fd"`,
		`/usr/bin/flock --shared "$catalog_fd"`,
		`/usr/bin/flock --shared "$control_fd"`,
		`/usr/bin/flock --shared "$shared_fd"`,
		`/usr/bin/flock --shared --nonblock --conflict-exit-code 75 "$migration_fd"`,
		`/usr/bin/flock --exclusive --nonblock --conflict-exit-code 75 "$oauth_fd"`,
		`if [[ $hold_catalog == false ]]`,
		`(exec 3<&- 4<&- 5<&- 6<&-; exec "$@") &`,
		`(exec 3<&- 4<&- 5<&- 6<&- 7<&-; exec "$@") &`,
		`while true; do`,
		`wait "$child_pid"`,
		`trap forward_term TERM`,
		`/usr/bin/readlink -- "$fd_path"`,
		`/usr/bin/stat -Lc '%u:%g:%a:%h:%s'`,
		`/usr/bin/awk '$1 == "flags:"`,
	)
	if strings.Index(helper, `/usr/bin/flock --exclusive "$activation_fd"`) >= strings.Index(helper, `/usr/bin/flock --shared "$catalog_fd"`) {
		t.Fatal("ChatForward activation lock must be acquired before the catalog lock")
	}
	loginStart := strings.Index(helper, "  chatforward-login)")
	loginEnd := -1
	if loginStart >= 0 {
		loginEnd = strings.Index(helper[loginStart:], "\n    ;;")
	}
	if loginStart < 0 || loginEnd < 0 || !strings.Contains(helper[loginStart:loginStart+loginEnd], "uses_activation=true") {
		t.Fatal("chatforward-login profile does not require the activation capability")
	}
	requireContains(t, helper,
		`--required-executable bin/workagent-admin`,
		`--required-executable chatforward/integration/login.sh`,
		`--required-executable chatforward/integration/readiness.mjs`,
		`--required-executable admin/smoke-chatforward-browser-sandbox`,
		`--required-executable chatforward/integration/run-browser.sh`,
	)
	for _, profile := range []string{
		"backup)", "healthcheck)", "notification)", "cliproxyapi)",
		"cliproxy-oauth-codex)", "cliproxy-oauth-kimi)", "cliproxy-oauth-doctor)",
		"chatforward)", "chatforward-browser)", "chatforward-login)", "chatforward-smoke)",
	} {
		requireContains(t, helper, profile)
	}
	if strings.Contains(helper, "tenant-config-reconcile)") || strings.Contains(helper, "reconcile-tenant-files") {
		t.Fatal("catalog-exclusive reconciliation must not run through a control-lock-retaining helper")
	}
	for _, profile := range []string{"cliproxyapi)", "cliproxy-oauth-codex)", "cliproxy-oauth-kimi)", "cliproxy-oauth-doctor)"} {
		start := strings.Index(helper, "  "+profile)
		if start < 0 {
			t.Fatalf("missing migration profile %s", profile)
		}
		end := strings.Index(helper[start:], "\n    ;;")
		if end < 0 || !strings.Contains(helper[start:start+end], "uses_migration=true") {
			t.Fatalf("profile %s does not adopt the CLIProxy migration lock", profile)
		}
	}
	for _, profile := range []string{"cliproxy-oauth-codex)", "cliproxy-oauth-kimi)"} {
		start := strings.Index(helper, "  "+profile)
		if start < 0 {
			t.Fatalf("provider authorization profile %s is missing", profile)
		}
		end := strings.Index(helper[start:], "\n    ;;")
		if end < 0 || !strings.Contains(helper[start:start+end], "uses_oauth_writer=true") {
			t.Fatalf("provider authorization profile %s does not require the OAuth writer lock", profile)
		}
	}
	doctorStart := strings.Index(helper, "  cliproxy-oauth-doctor)")
	if doctorStart < 0 {
		t.Fatal("OAuth doctor profile is missing")
	}
	doctorEnd := strings.Index(helper[doctorStart:], "\n    ;;")
	if doctorEnd < 0 || strings.Contains(helper[doctorStart:doctorStart+doctorEnd], "uses_oauth_writer=true") {
		t.Fatal("the read-only OAuth doctor must retain the four-lock ABI without adopting the writer lock")
	}
	if strings.Index(helper, `/usr/bin/flock --shared --nonblock --conflict-exit-code 75 "$migration_fd"`) >=
		strings.Index(helper, `/usr/bin/flock --exclusive --nonblock --conflict-exit-code 75 "$oauth_fd"`) {
		t.Fatal("OAuth writer lock must be acquired after the migration shared lock")
	}
	for _, profile := range []string{"backup)", "cliproxy-oauth-codex)", "cliproxy-oauth-kimi)", "cliproxy-oauth-doctor)", "chatforward-login)"} {
		start := strings.Index(helper, "  "+profile)
		if start < 0 {
			t.Fatalf("catalog-retaining profile %s is missing", profile)
		}
		end := strings.Index(helper[start:], "\n    ;;")
		if end < 0 || !strings.Contains(helper[start:start+end], "hold_catalog=true") {
			t.Fatalf("profile %s does not retain the catalog lock through its catalog-dependent child", profile)
		}
	}
	oauthRunbook := repositoryFile(t, "docs/CLIPROXY_OAUTH_LINUX.md")
	requireContains(t, oauthRunbook,
		"Every OAuth and doctor profile retains its complete lock set through child\nexit",
		"second Codex or Kimi flow fails immediately with status 75",
		"stricter than relying on the operator's active-service check",
		"fixed-root switching and catalog publication cannot\noverlap any OAuth/doctor command",
	)
	for _, forbidden := range []string{
		"/usr/bin/flock --shared 3 /",
		"/usr/bin/flock --shared 4 /",
		"/usr/bin/flock --shared 5 /",
		"control|shared ABSOLUTE_COMMAND",
	} {
		if strings.Contains(helper, forbidden) {
			t.Fatalf("v1 helper contains an open-ended or invalid lock protocol %q", forbidden)
		}
	}
}

func TestChatForwardInteractiveCommandsUseFixedRootLifecycleProfiles(t *testing.T) {
	runbook := repositoryFile(t, "docs/CHATFORWARD_LINUX.md")
	requireContains(t, runbook,
		"/usr/libexec/workagent-fixed-root-exec-v1 chatforward-smoke",
		"/usr/libexec/workagent-fixed-root-exec-v1 chatforward-login",
		"--unit=\"workagent-chatforward-smoke-${workagent_chatforward_smoke_id}.service\"",
		"--unit=\"workagent-chatforward-login-${workagent_chatforward_login_id}.service\"",
		"OpenFile=/run/workagent/activation.lock:workagent-activation-lock:read-only",
		"OpenFile=/run/workagent/release-config.lock:workagent-config-lock:read-only",
		"OpenFile=/opt/workagent/control.lock:workagent-control-release-lock:read-only",
		"OpenFile=/opt/workagent/shared.lock:workagent-shared-release-lock:read-only",
		"/usr/bin/google-chrome-stable",
	)
	login := repositoryFile(t, "components/chatforward/integration/login.sh")
	requireContains(t, login,
		`"$activation_guard" assert-activation-clean --lock-fd 3`,
		`exec 3<&-`,
	)
	activationGuard := repositoryFile(t, "cmd/workagent-admin/main.go")
	requireContains(t, activationGuard,
		"assertBackupQuiescenceCleanForInheritedActivation",
		"backupquiescence.AssertClean",
		"assertEdgePublicationCleanForInheritedActivation",
		"edgepublication.AssertClean",
		"return assertActivationStateCleanUnderAdoptedLock()",
		"refuse activation mutation with pending backup quiescence recovery",
		"refuse activation mutation with a pending edge publication",
	)
	for _, forbidden := range []string{
		"sudo --preserve-env=DISPLAY,XAUTHORITY",
		"sudo /opt/workagent/control/admin/smoke-chatforward-browser-sandbox",
	} {
		if strings.Contains(runbook, forbidden) {
			t.Fatalf("ChatForward runbook bypasses fixed-root lifecycle profile via %q", forbidden)
		}
	}
}

func TestFixedRootLifecycleSupervisorV1IsInstalledNoReplaceAndPreflighted(t *testing.T) {
	tmpfiles := repositoryFile(t, "deploy/tmpfiles.d/workagent.conf")
	requireContains(t, tmpfiles,
		"f /opt/workagent/control.lock 0600 root root -",
		"f /opt/workagent/shared.lock 0600 root root -",
		"f /run/workagent/fixed-root-exec-v1-install.lock 0600 root root -",
		"f /run/workagent/cliproxy-migration.lock 0640 root cliproxyapi -",
		"f /run/workagent/cliproxy-oauth.lock 0640 root cliproxyapi -",
	)
	installer := repositoryFile(t, "scripts/install-fixed-root-exec-v1.sh")
	requireContains(t, installer,
		"readonly destination=/usr/libexec/workagent-fixed-root-exec-v1",
		"readonly install_lock=/run/workagent/fixed-root-exec-v1-install.lock",
		"readonly source_file=$script_directory/../share/deploy/libexec/workagent-fixed-root-exec-v1",
		`if [[ -e $destination || -L $destination ]]; then`,
		`verify_installed || fail "the versioned destination exists with conflicting bytes or metadata"`,
		`ln -T -- "$staged" "$destination" || fail "the versioned destination appeared with conflicting state"`,
		`finish_linked_copy "$temporary"`,
		`reserved_temporaries=(/usr/libexec/.workagent-fixed-root-exec-v1.*)`,
		`/usr/bin/flock --exclusive 9`,
		`verify_abandoned_work_stage() {`,
		`if [[ $temporary_durable == false && -n $temporary ]] && verify_abandoned_work_stage "$temporary"; then`,
		`[[ $staged =~ ^/usr/libexec/\.workagent-fixed-root-exec-v1\.[A-Za-z0-9]{8}$ ]]`,
		`[[ $(stat -Lc '%u:%g:%a:%h' -- "$staged" 2>/dev/null || true) == 0:0:600:1 ]]`,
		`/usr/bin/dd if="$source_file" of="$temporary" bs=4096 conv=notrunc status=none`,
		`cmp -s -- "$source_file" "$temporary" || fail "the staged v1 helper copy does not match its source"`,
		`sync -f -- "$temporary" || fail "could not make the mode-0600 v1 helper copy durable"`,
		`chmod 0555 -- "$temporary"`,
		`sync -f -- /usr/libexec || fail "could not make the discarded work stage durable"`,
		`elif discard_abandoned_work_stage "$temporary"; then`,
		`sync -f -- /usr/libexec`,
	)
	for _, forbidden := range []string{"mv -f", "cp -f", "install -o root -g root -m 0555 -- \"$source_file\" \"$temporary\"", "install -m 0555 -- \"$source_file\" \"$destination\""} {
		if strings.Contains(installer, forbidden) {
			t.Fatalf("v1 installer can overwrite the immutable destination via %q", forbidden)
		}
	}
	preflight := repositoryFile(t, "scripts/production-preflight.sh")
	requireContains(t, preflight,
		`protected_lock_inode /opt/workagent/control.lock "control release lifecycle lock" 600`,
		`protected_lock_inode /opt/workagent/shared.lock "shared release lifecycle lock" 600`,
		`protected_lock_inode /run/workagent/fixed-root-exec-v1-install.lock "fixed-root supervisor v1 installer lock" 600`,
		`protected_service_lock_inode /run/workagent/cliproxy-migration.lock "CLIProxy migration lifecycle lock" cliproxyapi 640`,
		`protected_service_lock_inode /run/workagent/cliproxy-oauth.lock "CLIProxy OAuth writer lock" cliproxyapi 640`,
		`protected_executable /bin/bash "service lifecycle shell"`,
		`protected_executable /usr/bin/flock "service lifecycle lock helper"`,
		`protected_executable /usr/bin/awk "service lifecycle descriptor parser"`,
		`protected_executable /usr/bin/getent "service lifecycle group resolver"`,
		`protected_executable /usr/bin/readlink "service lifecycle path resolver"`,
		`protected_executable /usr/bin/stat "service lifecycle metadata inspector"`,
		`protected_canonical_root_directory /usr "immutable helper /usr ancestor"`,
		`protected_canonical_root_directory /usr/libexec "immutable helper libexec parent"`,
		`protected_root_file_exact /usr/libexec/workagent-fixed-root-exec-v1 "immutable fixed-root lifecycle supervisor v1" 555`,
		`cmp -s "$repository_root/deploy/libexec/workagent-fixed-root-exec-v1" /usr/libexec/workagent-fixed-root-exec-v1`,
	)
	runbook := repositoryFile(t, "deploy/README.md")
	requireContains(t, runbook,
		"power-crash state machine treats only an exact reserved-name,\nsingle-link, `0600 root:root` work inode as uncommitted and deletion-authorized",
		"fsyncs complete bytes before committing mode `0555`",
		"Any symlink, hard link, foreign owner, other mode, or\nconflicting destination fails closed",
	)
	sysusers := strings.Index(runbook, "systemd-sysusers \\")
	tmpfilesIndex := strings.Index(runbook, "systemd-tmpfiles --create \\")
	installerIndex := strings.Index(runbook, "/absolute/verified/final-source-gate/control-plane/admin/install-fixed-root-exec-v1")
	daemonReload := strings.Index(runbook, "systemctl daemon-reload")
	if sysusers < 0 || tmpfilesIndex < 0 || installerIndex < 0 || daemonReload < 0 ||
		sysusers >= tmpfilesIndex || tmpfilesIndex >= installerIndex || installerIndex >= daemonReload {
		t.Fatal("blank-host runbook does not create sysusers/tmpfiles state before the immutable helper install and daemon reload")
	}
	if strings.Count(runbook, "/absolute/verified/final-source-gate/control-plane/admin/install-fixed-root-exec-v1") != 1 {
		t.Fatal("blank-host runbook must invoke the immutable v1 installer exactly once")
	}
}
