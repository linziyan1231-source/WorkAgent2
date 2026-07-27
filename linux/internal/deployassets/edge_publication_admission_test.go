package deployassets

import (
	"strings"
	"testing"
)

const (
	edgeAdmissionExecStartPre  = "ExecStartPre=+/usr/libexec/workagent-edge-publication-admission-v1"
	edgeAdmissionExecStartPost = "ExecStartPost=+/usr/libexec/workagent-edge-publication-admission-v1 --watch $MAINPID"
)

func TestEdgePublicationAdmissionHelperIsIndependentPinnedAndFailClosed(t *testing.T) {
	requireRepositoryExecutable(t, "deploy/libexec/workagent-edge-publication-admission-v1")
	helper := repositoryFile(t, "deploy/libexec/workagent-edge-publication-admission-v1")
	requireContains(t, helper,
		"#!/bin/bash\n",
		"export LC_ALL=C",
		"export PATH=/usr/bin:/bin",
		"readonly activation_lock=/run/workagent/activation.lock",
		"readonly recovery_permit=/run/workagent-backup/recovery-activation.permit",
		"readonly recovery_journal=/var/lib/workagent-backup/recovery-activation.json",
		"readonly edge_permit=/run/workagent-edge/publication.permit",
		"readonly edge_journal=/var/lib/workagent-edge/publication.json",
		"readonly boot_id_path=/proc/sys/kernel/random/boot_id",
		"readonly caddy_executable=/usr/bin/caddy",
		"readonly caddy_account=caddy",
		"readonly caddy_process_name=caddy",
		"readonly caddy_cgroup='0::/system.slice/caddy.service'",
		"edge admission accepts only no arguments or --watch EXACT_MAINPID",
		"orphan edge publication permit exists without its durable journal",
		"blank-host recovery evidence conflicts with edge admission",
		"edge publication journal and permit do not cross-authorize their exact inodes",
		"edge publication evidence belongs to another boot",
		`prove_other_exclusive_owner "$permit_fd" "edge publication permit"`,
		`prove_other_exclusive_owner "$activation_fd" "tenant activation lock"`,
		`capture_caddy_process`,
		`validate_caddy_process`,
		`wait_for_released_permit "$permit_fd" || fail "edge publication permit release wait failed"`,
		`/usr/bin/flock --exclusive "$fd"`,
		`validate_open_artifact_descriptor "$journal_fd" "$journal_device" "$journal_inode" "$journal_size" 0 || fail "committed edge journal inode changed after permit release"`,
		`validate_open_artifact_descriptor "$permit_fd" "$permit_device" "$permit_inode" "$permit_size" 0 || fail "committed edge permit inode changed after permit release"`,
		`other_exclusive_owner "$activation_fd" || fail "tenant activation authority disappeared after edge commit"`,
		`/usr/bin/flock --unlock "$permit_fd" || fail "release admitted edge publication permit lock"`,
		`trap 'fail "edge publication watcher was interrupted before commit"' HUP INT TERM`,
	)
	if strings.Contains(helper, "workagent-recovery-activation-admission-v2") {
		t.Fatal("edge publication changed the immutable recovery admission protocol instead of using its independent v1 path")
	}
	if strings.Contains(helper, "systemctl") || strings.Contains(helper, "kill -TERM") || strings.Contains(helper, "kill -KILL") {
		t.Fatal("the synchronous post-start admission helper must report failure to systemd, not mutate or kill the unit itself")
	}
	if strings.Contains(helper, "while true") || strings.Contains(helper, "/usr/bin/sleep") {
		t.Fatal("the synchronous post-start admission helper polls instead of blocking once on the pinned permit FD")
	}
	waitStart := strings.Index(helper, "wait_for_released_permit() {")
	waitEnd := -1
	if waitStart >= 0 {
		waitEnd = strings.Index(helper[waitStart:], "\n}\n")
	}
	if waitStart < 0 || waitEnd < 0 {
		t.Fatal("edge watcher omits the native blocking permit-release wait")
	}
	waitBody := helper[waitStart : waitStart+waitEnd]
	if strings.Contains(waitBody, "--nonblock") || strings.Contains(waitBody, "sleep") {
		t.Fatal("permit-release handshake polls instead of blocking on the pinned permit FD")
	}
}

func TestCaddyUsesOneNativeBlockingPublicationWatcher(t *testing.T) {
	dropIn := repositoryFile(t, "deploy/systemd/caddy.service.d/workagent.conf")
	lines := strings.Split(dropIn, "\n")
	var preStarts []string
	postCount := 0
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "ExecStartPre="):
			preStarts = append(preStarts, line)
		case strings.HasPrefix(line, "ExecStartPost="):
			postCount++
			if line != edgeAdmissionExecStartPost {
				t.Fatalf("Caddy post-start watcher = %q, want %q", line, edgeAdmissionExecStartPost)
			}
		}
	}
	if len(preStarts) != 2 || preStarts[0] != coreAdmissionExecStartPre || preStarts[1] != edgeAdmissionExecStartPre || postCount != 1 {
		t.Fatalf("Caddy admission commands = pre:%q post:%d, want core then edge and exactly one watcher", preStarts, postCount)
	}
	requireContains(t, dropIn,
		"TimeoutStartSec=6min",
		"TimeoutStartFailureMode=kill",
		"KillMode=control-group",
		"SendSIGKILL=yes",
		"FinalKillSignal=SIGKILL",
		"Restart=no",
	)
	for _, forbidden := range []string{"&", "nohup", "Type=forking"} {
		if strings.Contains(dropIn, forbidden) {
			t.Fatalf("Caddy drop-in contains a detached watcher primitive %q", forbidden)
		}
	}
}

func TestEdgePublicationDirectoriesAndEvidenceAbsenceAreProvisioned(t *testing.T) {
	tmpfiles := repositoryFile(t, "deploy/tmpfiles.d/workagent.conf")
	requireContains(t, tmpfiles,
		"d /var/lib/workagent-edge 0700 root root -",
		"d /run/workagent-edge 0700 root root -",
	)
	for _, artifact := range []string{"/var/lib/workagent-edge/publication.json", "/run/workagent-edge/publication.permit"} {
		if strings.Contains(tmpfiles, artifact) {
			t.Fatalf("dynamic edge publication evidence is incorrectly created by tmpfiles: %s", artifact)
		}
	}
	preflight := repositoryFile(t, "scripts/production-preflight.sh")
	requireContains(t, preflight,
		`protected_executable /usr/libexec/workagent-edge-publication-admission-v1 "immutable edge publication admission helper v1"`,
		`protected_root_file_exact /usr/libexec/workagent-edge-publication-admission-v1 "immutable edge publication admission helper v1" 555`,
		`cmp -s "$repository_root/deploy/libexec/workagent-edge-publication-admission-v1" /usr/libexec/workagent-edge-publication-admission-v1`,
		`absent_path /run/workagent-edge/publication.permit "volatile edge publication permit"`,
		`absent_path /var/lib/workagent-edge/publication.json "unfinished edge publication journal"`,
	)
}

func TestEdgePublicationAdmissionHelperIsPackagedAndNoReplaceInstalled(t *testing.T) {
	requireRepositoryExecutable(t, "scripts/install-edge-publication-admission-v1.sh")
	installer := repositoryFile(t, "scripts/install-edge-publication-admission-v1.sh")
	requireContains(t, installer,
		"readonly destination=/usr/libexec/workagent-edge-publication-admission-v1",
		"readonly source_file=$script_directory/../share/deploy/libexec/workagent-edge-publication-admission-v1",
		"readonly stage_prefix=/usr/libexec/.workagent-edge-publication-admission-v1.",
		`ln -T -- "$staged" "$destination"`,
		`verify_copy "$temporary" 1`,
		`chmod 0555 -- "$temporary"`,
		`sync -f -- /usr/libexec`,
	)
	sourceGate := repositoryFile(t, "scripts/source-gate.sh")
	requireContains(t, sourceGate,
		`'deploy/libexec/workagent-edge-publication-admission-v1' \`,
		`install -m 0555 scripts/install-edge-publication-admission-v1.sh "$administration_directory/install-edge-publication-admission-v1"`,
		"admin/install-edge-publication-admission-v1",
		"share/deploy/libexec/workagent-edge-publication-admission-v1",
	)
	contract := repositoryFile(t, "cmd/workagent-release/main.go")
	requireContains(t, contract,
		`"admin/install-edge-publication-admission-v1"`,
		`"share/deploy/libexec/workagent-edge-publication-admission-v1"`,
	)
	releaseEvidence := repositoryFile(t, "docs/RELEASE_EVIDENCE.md")
	requireContains(t, releaseEvidence,
		"--required-executable admin/install-edge-publication-admission-v1",
		"--required-executable share/deploy/libexec/workagent-edge-publication-admission-v1",
	)
	runbook := repositoryFile(t, "deploy/README.md")
	requireContains(t, runbook,
		"/absolute/verified/final-source-gate/control-plane/admin/install-edge-publication-admission-v1",
		"/usr/libexec/workagent-edge-publication-admission-v1",
		"ExecStartPost",
		"TimeoutStartSec=6min",
	)
}
