package deployassets

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func repositoryFile(t *testing.T, relative string) string {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(repositoryRoot(t), relative))
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func requireRepositoryExecutable(t *testing.T, relative string) {
	t.Helper()
	path := filepath.Join(repositoryRoot(t), relative)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("repository executable %s is not a regular file", relative)
	}
	// Git records only whether a regular file is executable, not its complete
	// POSIX permission mask. The source gate deliberately materializes 100755
	// entries as 0700 beneath a private umask, while a normal checkout commonly
	// materializes the same entry as 0755. The owner's execute bit is the stable
	// property that proves the committed entry is executable in both contexts.
	permissions := info.Mode().Perm()
	if permissions&0o100 == 0 || permissions&0o022 != 0 {
		t.Fatalf("repository executable %s has unsafe mode %o (owner execute is required; group/other write is forbidden)", relative, permissions)
	}
}

func requireContains(t *testing.T, payload string, values ...string) {
	t.Helper()
	for _, value := range values {
		if !strings.Contains(payload, value) {
			t.Fatalf("deployment asset omitted %q", value)
		}
	}
}

func TestOnlyBytePinnedPatchesDisableGitWhitespaceDiagnostics(t *testing.T) {
	expected := []string{
		"components/aioncore/codex-acp-1.1.2-aionui-fork-steer.6.patch -whitespace",
		"components/aionui/aionui-webhost-workagent-runtime-auth.patch -whitespace",
		"components/kimi-code/kimi-code-0.29.1-acp-session-fork-steer.patch -whitespace",
		"components/kimi-code/kimi-code-0.29.1-minidb-resp-recovery.patch -whitespace",
		"third_party/cliproxyapi/patches/cliproxyapi-go1.26-hardening.patch -whitespace",
		"third_party/cliproxyapi/patches/cliproxyapi-per-key-models.patch -whitespace",
		"third_party/cliproxyapi/patches/cpa-key-policy-0.4.4-state-concurrency.patch -whitespace",
		"third_party/cliproxyapi/patches/cpa-key-policy-0.4.5-linux-directory-fsync.patch -whitespace",
	}
	var actual []string
	for _, line := range strings.Split(repositoryFile(t, ".gitattributes"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			actual = append(actual, line)
		}
	}
	if len(actual) != len(expected) {
		t.Fatalf("Git whitespace exception count drifted: got %d want %d", len(actual), len(expected))
	}
	for index := range expected {
		if actual[index] != expected[index] {
			t.Fatalf("Git whitespace exception %d drifted: got %q want %q", index, actual[index], expected[index])
		}
	}
}

func TestProductionExamplesUseTheMigratedHostContract(t *testing.T) {
	portalPath := filepath.Join(repositoryRoot(t), "config", "portal.example.json")
	portal, err := config.LoadPortal(portalPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := portal.ValidateProductionLayout("/etc/workagent/portal.json"); err != nil {
		t.Fatal(err)
	}
	if portal.Listener.PublicOrigin != "https://workagent.example.invalid" || portal.OutboundProxyURL != "http://127.0.0.1:8118" || portal.Runtime.MaxConcurrentInstances != 20 || portal.Runtime.IdleReapSeconds != 1800 || portal.Notifications.Endpoint != "http://127.0.0.1:25888/notification" || portal.Renderer.RelativeRoot != "static" {
		t.Fatalf("Portal production contract drifted: %#v", portal)
	}

	tenantRaw := repositoryFile(t, "config/tenant.example.json")
	var tenant config.Tenant
	if err := json.Unmarshal([]byte(tenantRaw), &tenant); err != nil {
		t.Fatal(err)
	}
	if err := tenant.Validate(); err != nil {
		t.Fatal(err)
	}
	if tenant.PortalOrigin != portal.Listener.PublicOrigin || tenant.OutboundProxyURL != portal.OutboundProxyURL || tenant.IdleReapSeconds != 1800 || tenant.Capacity.MaxInstances != 20 || tenant.Capacity.DiskHardLimitBytes != 20*1024*1024*1024 || !slices.Contains(tenant.Backend.RequiredReleaseFiles, filepath.Join(portal.Renderer.RelativeRoot, "index.html")) {
		t.Fatal("tenant example does not match the 20-instance/20-GiB migrated host contract")
	}

	chat := repositoryFile(t, "config/chatforward.example.env")
	requireContains(t, chat,
		"CHATFORWARD_PORTAL_URL=http://127.0.0.1:42580",
		"CHATFORWARD_MIRROR_URL=https://workagent.example.invalid/chatgpt/",
		"CHATFORWARD_CHROMIUM_BIN=/usr/bin/google-chrome-stable",
		"CHATFORWARD_OUTBOUND_PROXY_URL=http://127.0.0.1:8118",
	)
	for _, forbidden := range []string{"CHATFORWARD_SECRET", "CHATFORWARD_HOST=", "CHATFORWARD_PORT="} {
		if strings.Contains(chat, forbidden) {
			t.Fatalf("ChatForward environment contains forbidden override %q", forbidden)
		}
	}

	proxy := repositoryFile(t, "deploy/cliproxyapi/config.yaml")
	requireContains(t, proxy, "host: \"127.0.0.1\"", "allow-remote: false", "proxy-url: \"http://127.0.0.1:8118\"")
}

func TestChatForwardInteractiveLoginIsInsideTheSignedSharedContract(t *testing.T) {
	const loginPath = "chatforward/integration/login.sh"
	releaseEvidence := repositoryFile(t, "docs/RELEASE_EVIDENCE.md")
	loginRunbook := repositoryFile(t, "docs/CHATFORWARD_LINUX.md")
	lifecycleHelper := repositoryFile(t, "deploy/libexec/workagent-fixed-root-exec-v1")
	buildScript := repositoryFile(t, "scripts/build-chatforward.sh")
	requireContains(t, releaseEvidence, loginPath)
	requireContains(t, buildScript, "integration/login.sh")
	requireContains(t, loginRunbook,
		"/usr/libexec/workagent-fixed-root-exec-v1 chatforward-login",
		"/opt/workagent/shared/"+loginPath,
	)
	requireContains(t, lifecycleHelper,
		"--required chatforward/app/extension/manifest.json",
		"--required-executable "+loginPath,
		"--required-executable chatforward/integration/readiness.mjs",
		"--required-executable chatforward/node/bin/node",
	)
	for _, unsupported := range []string{"--manifest ", "--signature "} {
		if strings.Contains(loginRunbook, unsupported) {
			t.Fatalf("ChatForward login verification uses unsupported flag %q", unsupported)
		}
	}
}

func TestProductionUnitsFailClosedOnStorageDependenciesAndCredentials(t *testing.T) {
	portalDependencies := repositoryFile(t, "deploy/systemd/workagent-portal.service.d/chatforward.conf")
	requireContains(t, portalDependencies,
		"Requires=mihomo.service cliproxyapi.service workagent-notification.service workagent-chatforward.service",
		"RequiresMountsFor=/srv/workagent/users",
		"AssertPathIsMountPoint=/srv/workagent/users",
	)

	notification := repositoryFile(t, "deploy/systemd/workagent-notification.service")
	requireContains(t, notification,
		"LoadCredentialEncrypted=notifications-key:/etc/credstore.encrypted/workagent/notifications-key.cred",
		"ExecStartPost=/usr/bin/curl --noproxy *",
	)

	for _, relative := range []string{"deploy/systemd/cliproxyapi.service", "deploy/systemd/workagent-chatforward.service", "deploy/systemd/workagent-userhost@.service"} {
		requireContains(t, repositoryFile(t, relative), "mihomo.service")
	}
	userHost := repositoryFile(t, "deploy/systemd/workagent-userhost@.service")
	requireContains(t, userHost,
		"AssertPathIsMountPoint=/srv/workagent/users",
		"KillMode=control-group",
		"KeyringMode=private",
		"LimitCORE=0",
		"ProtectProc=invisible",
		"ProcSubset=pid",
	)
	const guardedTenantVerification = "ExecStartPre=+/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-admin verify-tenant --tenant-id %i --require-quiescent"
	guardedLines := 0
	for _, line := range strings.Split(userHost, "\n") {
		if !strings.HasPrefix(line, "ExecStartPre=+/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-admin verify-tenant") {
			continue
		}
		guardedLines++
		if line != guardedTenantVerification {
			t.Fatalf("tenant ExecStartPre must use the exact quiescent startup boundary: %q", line)
		}
	}
	if guardedLines != 1 {
		t.Fatalf("tenant unit has %d guarded verify-tenant lines, want exactly one", guardedLines)
	}

	backup := repositoryFile(t, "deploy/systemd/workagent-backup.service")
	requireContains(t, backup, "AssertPathIsMountPoint=/mnt/workagent-backup", "RequiresMountsFor=/mnt/workagent-backup")

	mount := repositoryFile(t, "deploy/systemd/srv-workagent-users.mount")
	requireContains(t, mount,
		"What=/var/lib/workagent-storage/tenants.xfs",
		"Where=/srv/workagent/users",
		"Type=xfs",
		"Options=loop,prjquota,nodev,nosuid",
	)
}

func TestEveryWorkAgentExecutableStartsFromAVerifiedSignedRoot(t *testing.T) {
	controlVerifier := "/opt/workagent/control/bin/workagent-release verify --root /opt/workagent/control --scope portal"
	for _, relative := range []string{
		"deploy/systemd/workagent-portal.service",
		"deploy/systemd/workagent-userhost@.service",
		"deploy/systemd/workagent-notification.service",
		"deploy/systemd/workagent-backup.service",
		"deploy/systemd/workagent-healthcheck.service",
		"deploy/systemd/cliproxyapi.service",
		"deploy/systemd/workagent-chatforward.service",
		"deploy/systemd/workagent-chatforward-browser.service",
	} {
		unit := repositoryFile(t, relative)
		requireContains(t, unit, controlVerifier)
		if strings.Contains(unit, "/opt/workagent/bin/") {
			t.Fatalf("%s can execute an unsigned legacy control-plane path", relative)
		}
	}
	sharedVerifier := "/opt/workagent/control/bin/workagent-release verify --root /opt/workagent/shared --scope shared"
	for _, relative := range []string{
		"deploy/systemd/cliproxyapi.service",
		"deploy/systemd/workagent-chatforward.service",
		"deploy/systemd/workagent-chatforward-browser.service",
	} {
		unit := repositoryFile(t, relative)
		requireContains(t, unit, sharedVerifier, "ConditionPathExists=/opt/workagent/shared/manifest.json")
		for _, forbidden := range []string{"/opt/workagent/cliproxyapi/", "/opt/workagent/chatforward/current/"} {
			if strings.Contains(unit, forbidden) {
				t.Fatalf("%s can execute unsigned shared-service path %s", relative, forbidden)
			}
		}
	}
	cliproxyUnit := repositoryFile(t, "deploy/systemd/cliproxyapi.service")
	requireContains(t, cliproxyUnit,
		"OpenFile=/run/workagent/cliproxy-migration.lock:workagent-cliproxy-migration-lock:read-only",
		"ExecStart=/usr/libexec/workagent-fixed-root-exec-v1 cliproxyapi ",
	)
	tmpfiles := repositoryFile(t, "deploy/tmpfiles.d/workagent.conf")
	requireContains(t, tmpfiles,
		"f /run/workagent/cliproxy-migration.lock 0640 root cliproxyapi -",
		"f /run/workagent/cliproxy-oauth.lock 0640 root cliproxyapi -",
	)

}

func TestBlankHostRecoveryInstallLockIsPrecreatedAndPreflighted(t *testing.T) {
	tmpfiles := repositoryFile(t, "deploy/tmpfiles.d/workagent.conf")
	requireContains(t, tmpfiles, "f /run/workagent-backup/recovery-install.lock 0600 root root -")
	preflight := repositoryFile(t, "scripts/production-preflight.sh")
	requireContains(t, preflight, `protected_lock_inode /run/workagent-backup/recovery-install.lock "blank-host recovery install lock" 600`)
	requireContains(t, preflight, `absent_path /run/workagent-backup/recovery-activation.permit "volatile blank-host recovery activation permit"`)
	requireContains(t, preflight, `absent_path /var/lib/workagent-backup/recovery-activation.json "unfinished blank-host recovery activation journal"`)
	requireContains(t, preflight, `absent_path /run/workagent-backup/quiesce.json "unfinished backup service quiescence journal"`)
	requireContains(t, preflight, `absent_path /var/lib/workagent/tenant-activation.json "unfinished tenant activation transaction journal" 755`)
}

func TestRuntimeLifecycleLocksAreSystemdProvisionedAndAdopted(t *testing.T) {
	tmpfiles := repositoryFile(t, "deploy/tmpfiles.d/workagent.conf")
	requireContains(t, tmpfiles, "f /run/workagent/release-config.lock 0600 root root -")
	requireContains(t, tmpfiles, "f /opt/workagent/aionui/current.json.lock 0600 root root -")
	for _, unit := range []string{"deploy/systemd/workagent-portal.service", "deploy/systemd/workagent-userhost@.service"} {
		payload := repositoryFile(t, unit)
		requireContains(t, payload, "OpenFile=/run/workagent/release-config.lock:workagent-config-lock:read-only")
		requireContains(t, payload, "OpenFile=/opt/workagent/aionui/current.json.lock:workagent-runtime-release-lock:read-only")
	}
	socket := repositoryFile(t, "deploy/systemd/workagent-userhost@.socket")
	requireContains(t, socket, "FileDescriptorName=workagent-userhost-socket")
	preflight := repositoryFile(t, "scripts/production-preflight.sh")
	requireContains(t, preflight, `protected_lock_inode /run/workagent/release-config.lock "release configuration lifecycle lock" 600`)
	requireContains(t, preflight, `protected_lock_inode /opt/workagent/aionui/current.json.lock "runtime release lifecycle lock" 600`)
}

func TestNotificationPayloadIsReadableOnlyThroughItsDedicatedServiceIdentity(t *testing.T) {
	tmpfiles := repositoryFile(t, "deploy/tmpfiles.d/workagent.conf")
	requireContains(t, tmpfiles, "d /etc/workagent 0751 root workagent -")
	if strings.Contains(tmpfiles, "d /etc/workagent 0750 root workagent -") {
		t.Fatal("notification service cannot traverse the protected configuration root")
	}
	unit := repositoryFile(t, "deploy/systemd/workagent-notification.service")
	requireContains(t, unit, "ExecStartPre=/usr/bin/test -r /etc/workagent/notification.json")
	preflight := repositoryFile(t, "scripts/production-preflight.sh")
	requireContains(t, preflight,
		`protected_service_file /etc/workagent/notification.json "installed notification payload" workagent-notification 640`,
		`protected_service_file /etc/workagent/chatforward.env "installed ChatForward environment" workagent-chatforward 640`,
		`protected_service_file /etc/cliproxyapi/config.yaml "installed CLIProxyAPI template" cliproxyapi 640`,
	)
	runbook := repositoryFile(t, "deploy/README.md")
	for _, required := range []string{
		"/usr/lib/sysusers.d/workagent.conf",
		"/usr/lib/sysusers.d/workagent-chatforward.conf",
		"/usr/lib/sysusers.d/workagent-notification.conf",
		"/usr/lib/tmpfiles.d/workagent.conf",
		"/usr/lib/tmpfiles.d/workagent-chatforward.conf",
		"/usr/lib/tmpfiles.d/workagent-caddy.conf",
		"/usr/lib/tmpfiles.d/workagent-monitoring.conf",
	} {
		requireContains(t, runbook, required)
	}
}

func TestTrackedComponentListsMatchTheExecutableReleaseContract(t *testing.T) {
	for scope, relative := range map[string]string{
		release.ScopeRuntime: "components/runtime/components.json",
		release.ScopeShared:  "components/shared/components.json",
	} {
		components, err := release.LoadComponents(filepath.Join(repositoryRoot(t), relative), false)
		if err != nil {
			t.Fatalf("load %s components: %v", scope, err)
		}
		actual := make(map[string]release.Component, len(components))
		for _, component := range components {
			actual[component.Name] = component
		}
		expected := release.ProductionRuntimeComponentEvidence()
		if scope == release.ScopeShared {
			expected = release.ProductionSharedComponentEvidence()
		}
		if len(actual) != len(expected) {
			t.Fatalf("%s component count drifted: got %d want %d", scope, len(actual), len(expected))
		}
		for name, component := range expected {
			if actual[name] != component {
				t.Fatalf("%s component %s drifted: got %+v want %+v", scope, name, actual[name], component)
			}
		}
	}
}

func TestRuntimeComponentSourcesBindTheQualifiedLinuxInputs(t *testing.T) {
	components, err := release.LoadComponents(filepath.Join(repositoryRoot(t), "components/runtime/components.json"), false)
	if err != nil {
		t.Fatal(err)
	}
	actual := make(map[string]string, len(components))
	for _, component := range components {
		actual[component.Name] = component.SourceRevision
	}
	expected := map[string]string{
		"aioncore":     "546ce672233f30e4821723c58d91bf6c868632388a3b55114d47c9d06981f317",
		"aionui":       "ec97e4aea496fdd7721e64e6c43e3d3ce97e181553961d8c2c63092d2b395f90",
		"codex":        "9a4a45314e80b53c4761b80067e3a68c2302f9a9026059b5f54f22dec8f34323",
		"kimi-code":    "d00c6a1eff46bfe4213fe9f0547b51d7d812f2e9acd2e335ef282bb8d78a97af",
		"noble-hashes": "b74fceb0006b617ed388254677b3d3847aeceb7e3f57db0cc9acc54644dabba6",
		"python":       "2ab91ff401783ccca64f75d10c882e957bdfd60e2bf5a72f8421793729b78a71",
	}
	if len(actual) != len(expected) {
		t.Fatalf("runtime source revision count drifted: got %d want %d", len(actual), len(expected))
	}
	for name, revision := range expected {
		if actual[name] != revision {
			t.Fatalf("runtime component %s source revision drifted: got %q want %q", name, actual[name], revision)
		}
	}
}

func TestSharedComponentSourcesBindTheQualifiedLinuxInputs(t *testing.T) {
	components, err := release.LoadComponents(filepath.Join(repositoryRoot(t), "components/shared/components.json"), false)
	if err != nil {
		t.Fatal(err)
	}
	actual := make(map[string]string, len(components))
	for _, component := range components {
		actual[component.Name] = component.SourceRevision
	}
	expected := map[string]string{
		"chatforward":           "a1b4d643c0cccde0f7d99483963974f0edb2c8107099627273534da7c0c054fe",
		"chatforward-extension": "a1b4d643c0cccde0f7d99483963974f0edb2c8107099627273534da7c0c054fe",
		"cliproxyapi":           "ca52365d3d123a1cff34a5020ce16507e3c2ef1032d57f171b9c26d2cd97eb16",
		"cliproxyapi-patch":     "cd8bcc9c683ed394ef4f58c90b3c61e9a5fea0265b9ae91a68259a16e7b43da8",
		"cpa-key-policy":        "bc0081c77764312a604add1013d9cb642f628978d967a46ca3f8159c63fa1a8f",
		"node":                  "472655581fb851559730c48763e0c9d3bc25975c59d518003fc0849d3e4ba0f6",
		"ws":                    "bb0f7e58ba1f64746672734d36175fe185f226491e336abc0743e2a8f4472ec1",
	}
	if len(actual) != len(expected) {
		t.Fatalf("shared source revision count drifted: got %d want %d", len(actual), len(expected))
	}
	for name, revision := range expected {
		if actual[name] != revision {
			t.Fatalf("shared component %s source revision drifted: got %q want %q", name, actual[name], revision)
		}
	}
}

func TestArtifactAssemblersRequireExternallyPinnedCompleteTrees(t *testing.T) {
	pins := map[string]string{
		"components/aioncore/LINUX-ARTIFACT-MANIFEST.sha256":    "6c79826411e8ed508c79a984d5f9bd99f556e8a2eb7fda6c022101c57663b12c  share/workagent-components/aioncore/SHA256SUMS\n",
		"components/aioncore/LINUX-ARTIFACT-TREE.sha256":        "08b05b39a9629a0eaf1f16f69e8b1c8b469e72e630213e50905526198493f2e4  canonical-tree\n",
		"components/aionui/LINUX-ARTIFACT-MANIFEST.sha256":      "5cd5b6bcc746a6345770638c3c799c44978c1f4c08f2089591bca8a74baafdae  share/workagent-components/aionui/SHA256SUMS\n",
		"components/aionui/LINUX-ARTIFACT-TREE.sha256":          "103f45055521ecca5b0f402b112b929454cb878aff635e095c6b0d7d35ff7e5d  canonical-tree\n",
		"components/chatforward/LINUX-ARTIFACT.sha256":          "aa86856f45b65a4a0727fb4068f6d7f6c778ad18a9c9a81a0d90ed3f3e07b4d0  workagent-chatforward-zombie-reap-20260725-2329-linux-x64.tar.gz\n",
		"components/cliproxyapi/LINUX-ARTIFACT-MANIFEST.sha256": "1d5039df7ed55aa78f5c870e42547092cd8c1b2b6a6088552f78861c6b2c7f8a  share/workagent-components/cliproxyapi/SHA256SUMS\n",
		"components/cliproxyapi/LINUX-ARTIFACT-TREE.sha256":     "88345b11939cad9c20d37c48c5555852ce3ade87e385db8bc436621b946ecd9f  canonical-tree\n",
		"components/cliproxyapi/LINUX-ARTIFACTS.sha256":         "53fb04859c69507be8b78965b4b54534d81c0216ef5f9cd2d460e2d6a460fa8c  bin/cli-proxy-api\n8c7026db39e717a4ee481843e451465f84d1e2bc2ba7f7b43e241b85a6cd5702  plugins/cpa-key-policy-v0.4.5.so\n",
		"components/codex/LINUX-ARTIFACT-MANIFEST.sha256":       "581e11abb1d173b4df5ee25da7e4efc18d1333a64b7f86f0992545f8b06537d3  share/workagent-components/codex/SHA256SUMS\n",
		"components/codex/LINUX-ARTIFACT-TREE.sha256":           "4eb453104a69d5d20e4298b4674820015d0df5afe1740b558d8da053cae65898  canonical-tree\n",
		"components/kimi-code/LINUX-ARTIFACT-MANIFEST.sha256":   "e6bb2d7cbe711dd2c0a9a4b07b15015281763d8c2d4ac596a199e80827c725cc  SHA256SUMS\n",
		"components/kimi-code/LINUX-ARTIFACT-TREE.sha256":       "4193a818f8d67dc80dfef3c2302999f42ba3f13d5bcfd3789f92224c29a3bb0a  canonical-tree\n",
		"components/python/LINUX-ARTIFACT-MANIFEST.sha256":      "d4d6812c442d431e79679851fa7cfe808360caeb246b306852d1c3aef8a520e5  share/workagent-components/python/SHA256SUMS\n",
		"components/python/LINUX-ARTIFACT-TREE.sha256":          "c74cd45be6b8b2754912e9ed246db74d7f2e610e1c6b4ef172ecc751665bc2b2  canonical-tree\n",
		"components/runtime/LINUX-PAYLOAD-MANIFEST.sha256":      "fc4b784aa0f4fcd65b8f4f9eba3e4683c7e64cb48576e60a13b6c579800e28ef  share/workagent-components/runtime/SHA256SUMS\n",
		"components/runtime/LINUX-PAYLOAD-TREE.sha256":          "0921ba54ab153bec177ae7e693f70ae2be213e3a971c8fa6b16ce7fe834137f5  canonical-tree\n",
	}
	for relative, expected := range pins {
		if actual := repositoryFile(t, relative); actual != expected {
			t.Fatalf("artifact pin %s drifted: got %q want %q", relative, actual, expected)
		}
	}

	for _, relative := range []string{"scripts/assemble-runtime-linux.sh", "scripts/assemble-shared-linux.sh", "scripts/smoke-runtime-linux.sh"} {
		info, err := os.Stat(filepath.Join(repositoryRoot(t), relative))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o111 == 0 {
			t.Fatalf("runtime release script is not executable: %s", relative)
		}
	}

	for _, relative := range []string{"scripts/assemble-runtime-linux.sh", "scripts/assemble-shared-linux.sh"} {
		assembler := repositoryFile(t, relative)
		requireContains(t, assembler,
			"verify_protected_input_path()",
			"verify_protected_input_file()",
			"verify_protected_input_tree()",
			`[[ ! -L $current ]] || fail`,
			`stat -c '%u %g %a' -- "$current"`,
			`[[ $uid == 0 && $gid == 0 ]] || fail`,
			`(( (8#$mode & 8#022) == 0 )) || fail`,
			`find "$root" \( ! -uid 0 -o ! -gid 0 \) -print -quit`,
			`find "$root" -perm /022 -print -quit`,
			"verify_complete_artifact_manifest()",
			"external artifact-manifest pin is missing or unsafe",
			"external artifact-manifest pin is malformed",
			"artifact manifest checksum mismatch",
			"external artifact-tree pin is missing or unsafe",
			"external artifact-tree pin is malformed",
			"canonical artifact tree checksum mismatch",
			`if (!valid_path(normalized) || normalized == manifest_path || seen[normalized]++) exit 1`,
			`find . -type f ! -path "./$manifest" -printf '%P\n' | sort`,
			`[[ $manifest_files == "$actual_files" ]]`,
			`sha256sum --strict --check "$manifest"`,
		)
		if strings.Contains(assembler, `mkdir -p -- "$(dirname`) {
			t.Fatalf("assembler recreates an unverified output parent: %s", relative)
		}
	}

	runtimeAssembler := repositoryFile(t, "scripts/assemble-runtime-linux.sh")
	requireContains(t, runtimeAssembler,
		"aionui-2.1.0-beta.editfork.21-linux-x64",
		"9edd87cdadb47d9d8398d8a708e636b8c595800bf0e495cb0a65e110c6e4e387",
		`== 2.1.0-beta.editfork.21 ]] || fail 'assembled AionUi version probe failed'`,
		`verify_protected_input_tree "$name artifact" "$root"`,
		`"$repo_root/scripts/assemble-runtime-linux.sh"`,
		`"$repo_root/components/aioncore/BINARY.sha256"`,
		`"$runtime_component_root/components.json"`,
		`"$repo_root/scripts/smoke-runtime-linux.sh"`,
		`verify_protected_input_path "runtime output parent" "$output_parent" directory`,
		`verify_protected_input_path "runtime work parent" "$work_parent" directory`,
		`verify_protected_input_path "runtime work directory" "$work_dir" directory`,
		`stat -c '%d' -- "$work_dir"`,
		`stat -c '%d' -- "$output_parent"`,
		`publication_status=0`,
		`mv -T --no-clobber -- "$stage" "$output_dir"`,
		`|| publication_status=$?`,
		`[[ ! -e $stage && ! -L $stage ]]`,
		`(( publication_status == 0 ))`,
		`[[ -d $output_dir && ! -L $output_dir ]]`,
	)
	if strings.Contains(runtimeAssembler, "aionui-2.1.0-beta.editfork.20-linux-x64") {
		t.Fatal("runtime assembler still defaults to the Windows-only AionUi reference identity")
	}
	for _, invocation := range []string{
		`verify_complete_artifact_manifest AionCore "$aioncore_dir" share/workagent-components/aioncore/SHA256SUMS`,
		`verify_complete_artifact_manifest AionUi "$aionui_dir" share/workagent-components/aionui/SHA256SUMS`,
		`verify_complete_artifact_manifest Codex "$codex_dir" share/workagent-components/codex/SHA256SUMS`,
		`verify_complete_artifact_manifest Kimi-Code "$kimi_dir" SHA256SUMS`,
		`verify_complete_artifact_manifest Python "$python_dir" share/workagent-components/python/SHA256SUMS`,
		`verify_complete_artifact_manifest Runtime-Payload "$stage" share/workagent-components/runtime/SHA256SUMS`,
	} {
		requireContains(t, runtimeAssembler, invocation)
	}
	sharedAssembler := repositoryFile(t, "scripts/assemble-shared-linux.sh")
	requireContains(t, sharedAssembler,
		`verify_complete_artifact_manifest CLIProxy "$cliproxy_root" share/workagent-components/cliproxyapi/SHA256SUMS`,
		`verify_protected_input_tree "CLIProxy artifact" "$cliproxy_root"`,
		`verify_protected_input_file "ChatForward artifact" "$chatforward_archive"`,
		`verify_protected_input_file "CLIProxy legacy manifest" "$cliproxy_manifest"`,
		`verify_protected_input_file "ChatForward legacy manifest" "$chatforward_manifest"`,
		`verify_protected_input_file "shared components inventory" "$components_json"`,
		`chatforward_archive_name=workagent-chatforward-zombie-reap-20260725-2329-linux-x64.tar.gz`,
		`[[ ${chatforward_archive##*/} != "$chatforward_archive_name" ]]`,
		`awk -v required_name="$chatforward_archive_name"`,
		`[[ $(hash_of "$chatforward_archive") == "$expected_chatforward_hash" ]]`,
		`verify_protected_input_path "shared output parent" "$output_parent" directory`,
		`verify_protected_input_path "shared work parent" "$work_parent" directory`,
		`verify_protected_input_path "shared work directory" "$work_directory" directory`,
		`stat -c '%d' -- "$work_directory"`,
		`stat -c '%d' -- "$output_parent"`,
		`publication_status=0`,
		`mv -T --no-clobber -- "$stage" "$output_directory"`,
		`|| publication_status=$?`,
		`[[ ! -e $stage && ! -L $stage ]]`,
		`(( publication_status == 0 ))`,
		`[[ -d $output_directory && ! -L $output_directory ]]`,
	)
}

func TestHostBoundCredentialCiphertextsAreNotBackupSources(t *testing.T) {
	backup := repositoryFile(t, "config/backup.example.json")
	secretCommand := repositoryFile(t, "cmd/workagent-secret/main.go")
	if strings.Contains(backup, "/etc/credstore.encrypted") || strings.Contains(backup, "/var/lib/systemd/credential.secret") {
		t.Fatal("production backup example includes host-bound systemd credential material")
	}
	for _, contract := range []string{
		`exec.Command("/usr/bin/systemd-creds", arguments...)`,
		`"encrypt", "--with-key=host", "--newline=no"`,
		`command.Stdin = bytes.NewReader(plaintext)`,
		`subtle.ConstantTimeCompare(decrypted, plaintext)`,
	} {
		requireContains(t, secretCommand, contract)
	}
}

func TestHostPreparationAndPreflightRetainExplicitBlockers(t *testing.T) {
	preparePath := filepath.Join(repositoryRoot(t), "scripts", "production-host-prepare.sh")
	info, err := os.Stat(preparePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("host preparation script is not executable")
	}
	prepare := repositoryFile(t, "scripts/production-host-prepare.sh")
	requireContains(t, prepare,
		"PREPARE-WORKAGENT-TENANT-STORAGE",
		"directory_is_empty",
		"workagent_services_inactive",
		"image_size_bytes=$((192 * 1024 * 1024 * 1024))",
		"backing_reserve_bytes=$((32 * 1024 * 1024 * 1024))",
		"readonly image_label=wa-tenants",
		"--replace-mount-unit",
	)

	preflight := repositoryFile(t, "scripts/production-preflight.sh")
	requireContains(t, preflight,
		"Production cutover is NOT authorized by this report.",
		"cloud ingress/ACME remains unresolved",
		"local-only backup is forbidden",
		"verified backup success metric is missing",
		"google-chrome-stable-150.0.7871.186-1.x86_64",
		"node_exporter-1.5.0-7.oc9.x86_64",
		`verified_rpm_payload google-chrome-stable "Google Chrome"`,
		`verified_rpm_payload node_exporter "node_exporter" /etc/sysconfig/node_exporter`,
		`NF == 3 && $1 ~ /^[SM5DLUGTP?.]{9}$/ && $2 == "c" && $3 == allowed`,
	)

	rpmVerifierPath := filepath.Join(repositoryRoot(t), "scripts", "verify-host-rpms.sh")
	verifierInfo, err := os.Stat(rpmVerifierPath)
	if err != nil {
		t.Fatal(err)
	}
	if verifierInfo.Mode().Perm()&0o111 == 0 {
		t.Fatal("host RPM verifier is not executable")
	}
	rpmVerifier := repositoryFile(t, "scripts/verify-host-rpms.sh")
	requireContains(t, rpmVerifier,
		"EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796",
		"0E225917414670F4442C250DFD533C07C264648F",
		"918565ec80808f179b9b768f173af200d9c97f0a424700a510084a8a593d2796",
		"d95208cac34108f4c9dd079b676ea9de093fe0517aa13b9b6fb67a8c396b81d4",
		`rpm --dbpath "$temporary_root/rpmdb" --verbose --checksig "$verified_chrome_rpm"`,
	)
	sourceGate := repositoryFile(t, "scripts/source-gate.sh")
	requireContains(t, sourceGate,
		`install -m 0555 scripts/verify-host-rpms.sh "$administration_directory/verify-host-rpms"`,
		`install -m 0555 scripts/smoke-chatforward-browser-sandbox.sh "$administration_directory/smoke-chatforward-browser-sandbox"`,
	)

	browserSmokePath := filepath.Join(repositoryRoot(t), "scripts", "smoke-chatforward-browser-sandbox.sh")
	browserSmokeInfo, err := os.Stat(browserSmokePath)
	if err != nil {
		t.Fatal(err)
	}
	if browserSmokeInfo.Mode().Perm()&0o111 == 0 {
		t.Fatal("ChatForward browser sandbox smoke is not executable")
	}
	browserSmoke := repositoryFile(t, "scripts/smoke-chatforward-browser-sandbox.sh")
	requireContains(t, browserSmoke,
		`readonly expected_chatforward_root=/opt/workagent/shared/chatforward`,
		"--property=DynamicUser=yes",
		"--property=PrivateNetwork=yes",
		"--property='RestrictNamespaces=user pid net'",
		"--property=NoNewPrivileges=yes --property=CapabilityBoundingSet= --property=AmbientCapabilities=",
		"CHATFORWARD_OUTBOUND_PROXY_URL=http://127.0.0.1:9",
		"probe_status != 124",
		"setuid sandbox is not running",
	)
	if strings.Contains(browserSmoke, "--no-sandbox") {
		t.Fatal("ChatForward browser sandbox smoke disables the browser sandbox")
	}
}

func TestSourceGatePackagesTheControlPlaneCommands(t *testing.T) {
	sourceGate := repositoryFile(t, "scripts/source-gate.sh")
	arrayFields := func(name string) []string {
		startMarker := name + "=(\n"
		start := strings.Index(sourceGate, startMarker)
		if start < 0 {
			t.Fatalf("source gate omits %s", name)
		}
		start += len(startMarker)
		end := strings.Index(sourceGate[start:], "\n)")
		if end < 0 {
			t.Fatalf("source gate contains an unterminated %s", name)
		}
		return strings.Fields(sourceGate[start : start+end])
	}
	wantControlCommands := []string{
		"workagent-admin", "workagent-backup", "workagent-cliproxy", "workagent-notification",
		"workagent-portal", "workagent-provision", "workagent-release", "workagent-secret", "workagent-userhost",
	}
	if got := arrayFields("go_control_commands"); !slices.Equal(got, wantControlCommands) {
		t.Fatalf("source gate Go control command set drifted: got %q want %q", got, wantControlCommands)
	}
	requireContains(t, sourceGate,
		"for command in \"${go_control_commands[@]}\"; do\n  CGO_ENABLED=0 $go_binary build",
		`-o "$binary_directory/$command" "./cmd/$command"`,
		"for command in \"${go_control_commands[@]}\"; do\n  verify_go_build_identity \"$binary_directory/$command\" \"$command\"",
	)
}

func TestTLSAndMonitoringNeverSubstituteLocalEvidenceForPublicReadiness(t *testing.T) {
	caddy := repositoryFile(t, "deploy/caddy/Caddyfile")
	requireContains(t, caddy,
		"workagent.example.invalid",
		"admin unix//run/caddy-admin/admin.sock",
		"auto_https disable_redirects",
		"request>uri delete",
		"request>headers delete",
		"roll_size 100MiB",
	)
	// Interim state approved by the owner: the cloud middlebox kills
	// TLS-ALPN-01 handshakes and port 80 is occupied by an unrelated workload,
	// so no public ACME path exists on this host. The edge serves the Caddy
	// internal CA until a publicly verifiable certificate path is restored.
	requireContains(t, caddy, "tls internal")
	if strings.Contains(caddy, "sslip.io") || strings.Contains(caddy, "issuer acme") {
		t.Fatal("Caddy contains a stale hostname or a broken ACME fallback")
	}
	if strings.Contains(caddy, "admin 127.0.0.1") {
		t.Fatal("Caddy administrative API is exposed to tenant-reachable loopback TCP")
	}
	caddyDropIn := repositoryFile(t, "deploy/systemd/caddy.service.d/workagent.conf")
	requireContains(t, caddyDropIn,
		"RuntimeDirectory=caddy-admin",
		"RuntimeDirectoryMode=0700",
		"AmbientCapabilities=CAP_NET_BIND_SERVICE",
		"CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
		"NoNewPrivileges=yes",
	)
	if strings.Contains(caddyDropIn, "CAP_NET_ADMIN") {
		t.Fatal("Caddy WorkAgent boundary retains host network-administration capability")
	}

	rules := repositoryFile(t, "deploy/monitoring/prometheus-rules.yml")
	requireContains(t, rules,
		"workagent_storage_backing_available_bytes < 34359738368",
		"absent(workagent_backup_last_success_timestamp_seconds)",
		"absent(probe_success{job=\"workagent-public\"})",
	)

	nodeExporter := repositoryFile(t, "deploy/node_exporter/node_exporter.sysconfig")
	requireContains(t, nodeExporter,
		"--web.listen-address=127.0.0.1:9100",
		"--collector.textfile.directory=/var/lib/node_exporter/textfile_collector",
	)

	journal := repositoryFile(t, "deploy/journald/99-workagent-production.conf")
	requireContains(t, journal, "SystemMaxUse=4G", "SystemKeepFree=16G", "MaxRetentionSec=30day")
}

func TestProductionRunbooksUseServiceScopedCLIProxyCredentials(t *testing.T) {
	oauth := repositoryFile(t, "docs/CLIPROXY_OAUTH_LINUX.md")
	requireContains(t, oauth,
		"systemd-run --quiet --wait --pty --collect --service-type=exec",
		"systemd-run --quiet --wait --pipe --collect --service-type=exec",
		"--unit=\"workagent-cliproxy-oauth-codex-${workagent_codex_oauth_run_id}.service\"",
		"--unit=\"workagent-cliproxy-oauth-kimi-${workagent_kimi_oauth_run_id}.service\"",
		"--unit=\"workagent-cliproxy-oauth-doctor-${workagent_oauth_doctor_run_id}.service\"",
		"--uid=cliproxyapi --gid=cliproxyapi",
		"--property='ReadWritePaths=/var/lib/cliproxyapi'",
		"--property=LoadCredentialEncrypted=cliproxy-management-key:/etc/credstore.encrypted/workagent/cliproxy-management-key.cred",
		"--property='OpenFile=/run/workagent/release-config.lock:workagent-config-lock:read-only'",
		"--property='OpenFile=/opt/workagent/control.lock:workagent-control-release-lock:read-only'",
		"--property='OpenFile=/opt/workagent/shared.lock:workagent-shared-release-lock:read-only'",
		"--property='OpenFile=/run/workagent/cliproxy-migration.lock:workagent-cliproxy-migration-lock:read-only'",
		"--property='OpenFile=/run/workagent/cliproxy-oauth.lock:workagent-cliproxy-oauth-lock:read-only'",
		"/usr/libexec/workagent-fixed-root-exec-v1 cliproxy-oauth-codex",
		"/usr/libexec/workagent-fixed-root-exec-v1 cliproxy-oauth-kimi",
		"/usr/libexec/workagent-fixed-root-exec-v1 cliproxy-oauth-doctor",
		"/opt/workagent/shared/cliproxyapi/bin/cli-proxy-api",
		"--codex-device-login --no-browser",
		"--kimi-login --no-browser",
		"/opt/workagent/control/bin/workagent-cliproxy doctor",
		"--credential %d/cliproxy-management-key",
	)
	if strings.Count(oauth, "--service-type=exec") != 3 || strings.Contains(oauth, "--property=Type=exec") {
		t.Fatal("OAuth transient service type contract is ambiguous or incomplete")
	}
	for _, lockOpen := range []string{
		"--property='OpenFile=/run/workagent/release-config.lock:workagent-config-lock:read-only'",
		"--property='OpenFile=/opt/workagent/control.lock:workagent-control-release-lock:read-only'",
		"--property='OpenFile=/opt/workagent/shared.lock:workagent-shared-release-lock:read-only'",
		"--property='OpenFile=/run/workagent/cliproxy-migration.lock:workagent-cliproxy-migration-lock:read-only'",
	} {
		if strings.Count(oauth, lockOpen) != 3 {
			t.Fatalf("every OAuth/doctor transient unit must receive %q", lockOpen)
		}
	}
	oauthWriterOpen := "--property='OpenFile=/run/workagent/cliproxy-oauth.lock:workagent-cliproxy-oauth-lock:read-only'"
	if strings.Count(oauth, oauthWriterOpen) != 2 {
		t.Fatalf("exactly the two provider authorization units must receive %q", oauthWriterOpen)
	}
	section := func(startMarker, endMarker string) string {
		t.Helper()
		start := strings.Index(oauth, startMarker)
		if start < 0 {
			t.Fatalf("OAuth runbook section %q is missing", startMarker)
		}
		end := len(oauth)
		if endMarker != "" {
			relativeEnd := strings.Index(oauth[start+len(startMarker):], endMarker)
			if relativeEnd < 0 {
				t.Fatalf("OAuth runbook section %q has no %q boundary", startMarker, endMarker)
			}
			end = start + len(startMarker) + relativeEnd
		}
		return oauth[start:end]
	}
	commonLockOpens := []string{
		"--property='OpenFile=/run/workagent/release-config.lock:workagent-config-lock:read-only'",
		"--property='OpenFile=/opt/workagent/control.lock:workagent-control-release-lock:read-only'",
		"--property='OpenFile=/opt/workagent/shared.lock:workagent-shared-release-lock:read-only'",
		"--property='OpenFile=/run/workagent/cliproxy-migration.lock:workagent-cliproxy-migration-lock:read-only'",
	}
	for name, body := range map[string]string{
		"Codex":  section("## Authorize Codex", "## Authorize Kimi"),
		"Kimi":   section("## Authorize Kimi", "## Enforce full readiness"),
		"doctor": section("## Enforce full readiness", ""),
	} {
		previous := -1
		for _, lockOpen := range commonLockOpens {
			index := strings.Index(body, lockOpen)
			if index < 0 || index <= previous {
				t.Fatalf("%s transient unit does not preserve the common fd 3-6 order", name)
			}
			previous = index
		}
		writerIndex := strings.Index(body, oauthWriterOpen)
		if name == "doctor" {
			if writerIndex >= 0 {
				t.Fatal("read-only OAuth doctor unexpectedly receives the writer descriptor")
			}
		} else if writerIndex <= previous || strings.Count(body, oauthWriterOpen) != 1 {
			t.Fatalf("%s authorization unit does not receive exactly one writer lock after fd 6", name)
		}
	}
	if strings.Contains(oauth, "/usr/bin/flock --shared --no-fork 3 ") || strings.Contains(oauth, "/usr/bin/flock --shared 3 /opt/") {
		t.Fatal("OAuth runbook uses numeric descriptor flock in the invalid command/path form")
	}
	for _, pathDependent := range []string{"\nworkagent-", "\nsystemctl ", "\nsystemd-run ", "\ntest "} {
		if strings.Contains(oauth, pathDependent) {
			t.Fatalf("OAuth runbook invokes a command through PATH: %q", pathDependent)
		}
	}

	docPaths, err := filepath.Glob(filepath.Join(repositoryRoot(t), "docs", "*.md"))
	if err != nil || len(docPaths) == 0 {
		t.Fatal("production documentation inventory is unavailable")
	}
	relatives := []string{"deploy/README.md"}
	for _, path := range docPaths {
		relative, err := filepath.Rel(repositoryRoot(t), path)
		if err != nil {
			t.Fatal(err)
		}
		relatives = append(relatives, relative)
	}
	for _, relative := range relatives {
		if strings.Contains(repositoryFile(t, relative), "/run/credentials/cliproxyapi.service/cliproxy-management-key") {
			t.Fatalf("%s tells a host shell to read a service-private credential path", relative)
		}
	}
}
