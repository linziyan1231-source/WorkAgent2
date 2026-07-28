package deployassets

import (
	"strings"
	"testing"
)

const (
	coreAdmissionExecStartPre     = "ExecStartPre=+/usr/libexec/workagent-core-activation-admission-v1"
	recoveryAdmissionExecStartPre = "ExecStartPre=+/usr/libexec/workagent-recovery-activation-admission-v1"
)

func TestRecoveryActivationAdmissionHelperIsPinnedAndFailClosed(t *testing.T) {
	requireRepositoryExecutable(t, "deploy/libexec/workagent-recovery-activation-admission-v1")
	helper := repositoryFile(t, "deploy/libexec/workagent-recovery-activation-admission-v1")
	requireContains(t, helper,
		"#!/bin/bash\n",
		"export LC_ALL=C",
		"export PATH=/usr/bin:/bin",
		"readonly activation_lock=/run/workagent/activation.lock",
		"readonly recovery_permit=/run/workagent-backup/recovery-activation.permit",
		"readonly recovery_install_lock=/run/workagent-backup/recovery-install.lock",
		"readonly recovery_journal=/var/lib/workagent-backup/recovery-activation.json",
		"readonly boot_id_path=/proc/sys/kernel/random/boot_id",
		"if [[ ! -e $recovery_journal && ! -L $recovery_journal ]]",
		"if [[ -e $recovery_permit || -L $recovery_permit ]]",
		"fail \"orphan recovery activation permit exists without its durable journal\"",
		"regular\\ file:0:0:600:1:([1-9][0-9]*)",
		`if ! exec {permit_fd}<"$recovery_permit"; then`,
		`if ! exec {install_lock_fd}<"$recovery_install_lock"; then`,
		`if ! exec {activation_fd}<"$activation_lock"; then`,
		`IFS= read -r -N 38 boot_payload <&"$boot_fd"`,
		`[[ $permit_boot_id == "$current_boot_id" ]] || fail "recovery activation permit belongs to another boot"`,
		`[[ $permit_install_lock_device != "$install_lock_device" || $permit_install_lock_inode != "$install_lock_inode" ]]`,
		"readonly activation_shape='0:0:600:1:0'",
		"/usr/bin/stat -c '%d:%i' -- \"$activation_lock\"",
		"/usr/bin/stat -Lc '%d:%i' -- \"/proc/self/fd/$activation_fd\"",
		"/usr/bin/readlink -- \"/proc/self/fd/$activation_fd\"",
		"(( (8#$flags & 3) == 0 ))",
		"/usr/bin/flock --exclusive --nonblock --conflict-exit-code 75 \"$permit_fd\"",
		"/usr/bin/flock --exclusive --nonblock --conflict-exit-code 75 \"$install_lock_fd\"",
		"/usr/bin/flock --exclusive --nonblock --conflict-exit-code 75 \"$activation_fd\"",
		"fail \"recovery activation journal is pending without an active recovery\"",
	)
	if strings.Count(helper, "/usr/bin/flock --exclusive --nonblock --conflict-exit-code 75 \"$activation_fd\"") < 2 {
		t.Fatal("recovery admission helper must repeat the nonblocking conflict proof after pathname revalidation")
	}
	if strings.Count(helper, "/usr/bin/flock --exclusive --nonblock --conflict-exit-code 75 \"$permit_fd\"") < 2 {
		t.Fatal("recovery admission helper must repeat its recovery-specific volatile permit proof")
	}
	if strings.Count(helper, "/usr/bin/flock --exclusive --nonblock --conflict-exit-code 75 \"$install_lock_fd\"") < 2 {
		t.Fatal("recovery admission helper must repeat its permit-bound install-lock ownership proof")
	}
}

func TestEveryRecoveryActivatedServiceRunsAdmissionFirst(t *testing.T) {
	services := []string{
		"deploy/systemd/cliproxyapi.service",
		"deploy/systemd/workagent-notification.service",
		"deploy/systemd/workagent-chatforward.service",
		"deploy/systemd/workagent-chatforward-browser.service",
		"deploy/systemd/workagent-portal.service",
		"deploy/systemd/workagent-userhost@.service",
		"deploy/systemd/workagent-tenant-config-reconcile.service",
	}
	for _, path := range services {
		t.Run(path, func(t *testing.T) {
			unit := repositoryFile(t, path)
			requireContains(t, unit,
				"ConditionFileIsExecutable=/usr/libexec/workagent-recovery-activation-admission-v1",
				"ConditionPathExists=/run/workagent/activation.lock",
			)
			var preStarts []string
			for _, line := range strings.Split(unit, "\n") {
				if strings.HasPrefix(line, "ExecStartPre=") {
					preStarts = append(preStarts, line)
				}
			}
			if len(preStarts) < 2 || preStarts[0] != coreAdmissionExecStartPre || preStarts[1] != recoveryAdmissionExecStartPre {
				t.Fatalf("first pre-start commands = %q, want exact core then recovery admission", preStarts)
			}
		})
	}
}

func TestTenantSocketCannotListenBeforeCatalogAdmission(t *testing.T) {
	socket := repositoryFile(t, "deploy/systemd/workagent-userhost@.socket")
	requireContains(t, socket,
		"Requires=workagent-tenant-catalog-ready.target",
		"After=workagent-tenant-catalog-ready.target",
		"ConditionFileIsExecutable=/usr/libexec/workagent-core-activation-admission-v1",
		"ConditionFileIsExecutable=/usr/libexec/workagent-recovery-activation-admission-v1",
		"ConditionPathExists=/run/workagent/activation.lock",
	)
	target := repositoryFile(t, "deploy/systemd/workagent-tenant-catalog-ready.target")
	requireContains(t, target,
		"Requires=workagent-tenant-config-reconcile.service",
		"After=workagent-tenant-config-reconcile.service",
		"ConditionFileIsExecutable=/usr/libexec/workagent-core-activation-admission-v1",
		"ConditionFileIsExecutable=/usr/libexec/workagent-recovery-activation-admission-v1",
		"ConditionPathExists=/run/workagent/activation.lock",
	)
}

func TestRecoveryActivationAdmissionHelperIsPackagedInstalledAndPreflighted(t *testing.T) {
	requireRepositoryExecutable(t, "scripts/install-admission-helper-v1.sh")
	installer := repositoryFile(t, "scripts/install-admission-helper-v1.sh")
	requireContains(t, installer,
		"core-activation | edge-publication | recovery-activation",
		"readonly destination=/usr/libexec/$helper_name",
		"readonly source_file=$script_directory/../share/deploy/libexec/$helper_name",
		"readonly stage_prefix=/usr/libexec/.$helper_name.",
		`ln -T -- "$staged" "$destination"`,
		`verify_copy "$temporary" 1`,
		`chmod 0555 -- "$temporary"`,
		`sync -f -- /usr/libexec`,
	)
	sourceGate := repositoryFile(t, "scripts/source-gate.sh")
	requireContains(t, sourceGate,
		`'deploy/libexec/workagent-recovery-activation-admission-v1' > "$shell_file_inventory"`,
		`install -m 0555 scripts/install-admission-helper-v1.sh "$administration_directory/install-recovery-activation-admission-v1"`,
		"admin/install-recovery-activation-admission-v1",
		"share/deploy/libexec/workagent-recovery-activation-admission-v1",
	)
	preflight := repositoryFile(t, "scripts/production-preflight.sh")
	requireContains(t, preflight,
		`protected_root_file_exact /usr/libexec/workagent-recovery-activation-admission-v1 "immutable recovery activation admission helper v1" 555`,
		`cmp -s "$repository_root/deploy/libexec/workagent-recovery-activation-admission-v1" /usr/libexec/workagent-recovery-activation-admission-v1`,
		`absent_path /run/workagent-backup/recovery-activation.permit "volatile blank-host recovery activation permit"`,
		`absent_path /var/lib/workagent-backup/recovery-activation.json "unfinished blank-host recovery activation journal"`,
		`absent_path /run/workagent-backup/quiesce.json "unfinished backup service quiescence journal"`,
		`absent_path /var/lib/workagent/tenant-activation.json "unfinished tenant activation transaction journal" 755`,
	)
}

func TestBlankHostRecoveryOwnsVolatilePermitAndRejectsTenantTransactionFirst(t *testing.T) {
	source := repositoryFile(t, "internal/backup/recovery_linux.go")
	permitSource := repositoryFile(t, "internal/backup/recovery_activation_linux.go")
	requireContains(t, permitSource,
		"func acquireAuthorizedRecoveryActivationPermit(installLock *recoveryInstallLockGuard, journalPath, bootID string)",
		"InstallLockDevice uint64 `json:\"install_lock_device\"`",
		"InstallLockInode  uint64 `json:\"install_lock_inode\"`",
		"requireRecoveryExclusiveLockHeld(recoveryInstallLockPath, openRecoveryControlParent)",
		"requireRecoveryExclusiveLockHeld(recoveryActivationLockPath, openRecoveryActivationLockParent)",
		"return acquireRecoveryActivationPermit(recoveryActivationPermitPath, journalPath, bootID, installLock, openRecoveryControlParent)",
	)
	firstTenantProof := strings.Index(source, "if err := admin.AssertTenantActivationClean(); err != nil")
	installLock := strings.Index(source, "installLock, err := acquireRecoveryInstallLock(recoveryInstallLockPath)")
	activationLock := strings.Index(source, "activationGuard, err := lifecyclelock.AcquireActivationExclusive(ctx)")
	if firstTenantProof < 0 || installLock < 0 || activationLock < 0 || firstTenantProof >= installLock || installLock >= activationLock {
		t.Fatal("blank-host recovery does not reject a tenant activation journal before its first volatile write and A_EX acquisition")
	}
	remaining := source[activationLock:]
	secondTenantProof := strings.Index(remaining, "if err := admin.AssertTenantActivationClean(); err != nil")
	stalePermit := strings.Index(remaining, "reconcileStaleRecoveryActivationPermit(recoveryActivationPermitPath")
	rollbackJournal := strings.Index(remaining, "rollbackRecoveryActivation(controller, recoveryActivationJournalPath)")
	if secondTenantProof < 0 || stalePermit < 0 || rollbackJournal < 0 || secondTenantProof >= stalePermit || stalePermit >= rollbackJournal {
		t.Fatal("blank-host recovery does not reprove tenant activation cleanliness under A_EX before stale-permit/journal mutation")
	}
	writeJournal := strings.Index(source, "writeRecoveryActivationJournal(recoveryActivationJournalPath, activationJournal)")
	createPermit := strings.Index(source, "acquireAuthorizedRecoveryActivationPermit(installLock, recoveryActivationJournalPath, bootID)")
	firstEnable := strings.Index(source, `recoverySystemdActionUnits(ctx, controller, "enable", enableUnits)`)
	closePermit := strings.LastIndex(source, "activationPermit.Close()")
	removeJournal := strings.LastIndex(source, "removeRecoveryActivationJournal(recoveryActivationJournalPath)")
	if writeJournal < 0 || createPermit < 0 || firstEnable < 0 || closePermit < 0 || removeJournal < 0 ||
		writeJournal >= createPermit || createPermit >= firstEnable || closePermit >= removeJournal {
		t.Fatal("blank-host recovery permit is not durably journal-bound, held before enable, and revoked before journal commit")
	}
	tmpfiles := repositoryFile(t, "deploy/tmpfiles.d/workagent.conf")
	if strings.Contains(tmpfiles, "recovery-activation.permit") {
		t.Fatal("the same-boot recovery permit must be dynamically published, not recreated by tmpfiles at boot")
	}
	runbook := repositoryFile(t, "deploy/README.md")
	requireContains(t, runbook,
		"/absolute/verified/final-source-gate/control-plane/admin/install-fixed-root-exec-v1\n/absolute/verified/final-source-gate/control-plane/admin/install-recovery-activation-admission-v1",
		"A generic administrator holding only the activation lock—or relocking a stale same-boot permit while substituting another install-lock inode—is therefore not recovery authorization.",
	)
}
