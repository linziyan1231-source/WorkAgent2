//go:build linux

package cliproxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/posixacl"
)

type migrationReceiptTestCloser struct {
	closed *bool
}

type migrationReceiptSystemdFixture struct {
	properties map[string]string
	err        error
}

func (fixture migrationReceiptSystemdFixture) Properties(_ context.Context, unit string, names ...string) (map[string]string, error) {
	if fixture.err != nil {
		return nil, fixture.err
	}
	if unit != migrationLiveReceiptService {
		return nil, errors.New("unexpected unit")
	}
	result := make(map[string]string, len(names))
	for _, name := range names {
		if value, ok := fixture.properties[name]; ok {
			result[name] = value
		}
	}
	return result, nil
}

func (migrationReceiptSystemdFixture) Action(context.Context, ...string) error {
	return errors.New("unexpected action")
}

func migrationReceiptSystemdProperties() map[string]string {
	return map[string]string{
		"LoadState": "loaded", "ActiveState": "active", "SubState": "running", "User": "cliproxyapi", "Group": "cliproxyapi",
		"MainPID": "4242", "ControlPID": "0",
		"Result": "success", "InvocationID": "11111111111141118111111111111111", "ActiveEnterTimestampMonotonic": "123456",
		"FragmentPath": migrationLiveReceiptFragment, "DropInPaths": "", "NeedDaemonReload": "no",
	}
}

func migrationReceiptTestFragmentDigest(path string) (string, error) {
	if !migrationReceiptTrustedFragmentPath(path) {
		return "", errors.New("untrusted test fragment")
	}
	return strings.Repeat("9", 64), nil
}

func (closer *migrationReceiptTestCloser) Close() error {
	if closer != nil && closer.closed != nil {
		*closer.closed = true
	}
	return nil
}

func migrationReceiptTestPath(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, migrationLiveReceiptName)
}

func migrationReceiptTestEvidence() migrationReceiptBoundEvidence {
	tenantID := "11111111-1111-4111-8111-111111111111"
	hash := func(character string) string { return strings.Repeat(character, 64) }
	return migrationReceiptBoundEvidence{
		Report: migrationReceiptReport{
			Path: "/var/lib/workagent/migration/report.json", SHA256: hash("a"),
			SourceFingerprint: hash("b"), OutputFingerprint: hash("c"),
		},
		Plan: migrationReceiptPlan{Path: "/var/lib/workagent/migration/cutover/cliproxy-quota-overrides.json", SHA256: hash("d")},
		Portal: migrationReceiptPortal{
			DatabasePath: "/var/lib/workagent/portal/portal.db", Users: 1, IdentityCatalogSHA256: hash("e"),
		},
		PendingBundles: []migrationReceiptPending{{
			TenantID: tenantID, Path: "/srv/workagent/users/" + tenantID + "/credentials/model-bootstrap-v1.pending.json",
			BundleSHA256: hash("f"), StateSHA256: hash("1"), BundleVersion: 1,
		}},
		PolicyState: migrationReceiptPolicyState{
			Path: "/var/lib/cliproxyapi/policy/cpa-key-policy-state.json", SHA256: hash("2"), Size: 1234, UID: 991, GID: 991,
		},
		InputContract: hash("3"), LiveCatalog: hash("4"), LiveKeys: hash("5"),
		ServiceGeneration: migrationReceiptServiceGeneration{
			Unit: migrationLiveReceiptService, LoadState: "loaded", ActiveState: "active", SubState: "running",
			User: "cliproxyapi", Group: "cliproxyapi", MainPID: 4242, ControlPID: 0, Result: "success",
			InvocationID:                  "11111111111141118111111111111111",
			ActiveEnterTimestampMonotonic: 123456, FragmentPath: migrationLiveReceiptFragment,
			FragmentSHA256: strings.Repeat("9", 64), DropInPaths: "", NeedDaemonReload: "no",
		},
	}
}

func migrationReceiptTestReceipt(t *testing.T, path string, now time.Time, evidence migrationReceiptBoundEvidence, catalog, keys string) migrationLiveVerificationReceipt {
	t.Helper()
	if catalog == "" {
		catalog = strings.Repeat("4", 64)
	}
	if keys == "" {
		keys = strings.Repeat("5", 64)
	}
	evidence.LiveCatalog, evidence.LiveKeys = catalog, keys
	receipt, _, err := buildMigrationLiveVerificationReceipt(path, now, evidence)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func TestMigrationLiveReceiptCanonicalLiveProofDigests(t *testing.T) {
	keys := []listedKey{
		{
			ID: "key-b", Name: "B", Enabled: true, KeyPreview: "cpa_…BBBB", RPM: 2,
			Models:        []json.RawMessage{json.RawMessage(`{"target":"model","provider":"p"}`)},
			Aliases:       []json.RawMessage{json.RawMessage(`{"target":"model","alias":"b"}`)},
			DailyLimitUSD: "2", WeeklyLimitUSD: "3", AllowModelsEndpoint: true,
			Usage: json.RawMessage(`{"daily":{"total_usd":1}}`), CreatedAt: "old", UpdatedAt: "old",
		},
		{
			ID: "key-a", Name: "A", Enabled: true, KeyPreview: "cpa_…AAAA", RPM: 1,
			Models:        []json.RawMessage{json.RawMessage(`{"provider":"p","target":"model"}`)},
			Aliases:       []json.RawMessage{json.RawMessage(`{"alias":"a","target":"model"}`)},
			DailyLimitUSD: "1", WeeklyLimitUSD: "2", AllowModelsEndpoint: true,
		},
	}
	first, err := canonicalLiveKeysDigest(keys)
	if err != nil {
		t.Fatal(err)
	}
	reordered := []listedKey{keys[1], keys[0]}
	reordered[0].Models = []json.RawMessage{json.RawMessage(`{"target":"model","provider":"p"}`)}
	reordered[0].Usage = json.RawMessage(`{"daily":{"total_usd":999}}`)
	reordered[0].CreatedAt, reordered[0].UpdatedAt = "new", "new"
	second, err := canonicalLiveKeysDigest(reordered)
	if err != nil || second != first {
		t.Fatalf("stable live key proof changed with ordering or mutable usage: %q %q %v", first, second, err)
	}
	reordered[0].Enabled = false
	changed, err := canonicalLiveKeysDigest(reordered)
	if err != nil || changed == first {
		t.Fatal("stable live key proof omitted enabled contract drift")
	}

	catalog := map[string]catalogAlias{
		"b": {Alias: "B", Targets: []catalogTarget{{Provider: "p", TargetModel: "b"}}, InputPricePerMillion: "2", OutputPricePerMillion: "3"},
		"a": {Alias: "A", Targets: []catalogTarget{{Provider: "p", TargetModel: "a"}}, InputPricePerMillion: "1", OutputPricePerMillion: "2"},
	}
	catalogFirst, err := canonicalLiveCatalogDigest(catalog)
	if err != nil {
		t.Fatal(err)
	}
	catalogSecond, err := canonicalLiveCatalogDigest(map[string]catalogAlias{"a": catalog["a"], "b": catalog["b"]})
	if err != nil || catalogFirst != catalogSecond {
		t.Fatal("live catalog proof depends on map iteration order")
	}
	changedAlias := catalog["a"]
	changedAlias.Targets = []catalogTarget{{Provider: "different", TargetModel: "a"}}
	catalogChanged, err := canonicalLiveCatalogDigest(map[string]catalogAlias{"a": changedAlias, "b": catalog["b"]})
	if err != nil || catalogChanged == catalogFirst {
		t.Fatal("live catalog proof omitted target contract drift")
	}
}

func TestMigrationReceiptPortalSummaryBindsEnabledCatalog(t *testing.T) {
	user := portalMigrationUser{
		Username: "Alice", UsernameNorm: "alice", TenantID: "11111111-1111-4111-8111-111111111111",
		RuntimeUser: "workagent_alice", DataRoot: "/srv/workagent/users/11111111-1111-4111-8111-111111111111",
	}
	disabled, err := summarizeMigrationReceiptPortal("/var/lib/workagent/portal/portal.db", []portalMigrationUser{user})
	if err != nil {
		t.Fatal(err)
	}
	user.Enabled = true
	enabled, err := summarizeMigrationReceiptPortal("/var/lib/workagent/portal/portal.db", []portalMigrationUser{user})
	if err != nil {
		t.Fatal(err)
	}
	if disabled.IdentityCatalogSHA256 == enabled.IdentityCatalogSHA256 {
		t.Fatal("Portal receipt catalog omitted the enabled bit")
	}
}

func TestMigrationLiveReceiptServiceGenerationClosesStoppedRestartedAndSourceDrift(t *testing.T) {
	properties := migrationReceiptSystemdProperties()
	generation, err := summarizeMigrationReceiptServiceGenerationWithFragment(
		context.Background(), migrationReceiptSystemdFixture{properties: properties}, migrationReceiptTestFragmentDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if generation.MainPID != 4242 || generation.InvocationID != properties["InvocationID"] ||
		generation.FragmentPath != migrationLiveReceiptFragment || generation.FragmentSHA256 != strings.Repeat("9", 64) {
		t.Fatalf("service generation summary is incomplete: %#v", generation)
	}
	generationSHA256, err := migrationReceiptJSONSHA256(generation)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateMigrationReceiptServiceGenerationWithControllerAndFragment(
		context.Background(), generationSHA256, migrationReceiptSystemdFixture{properties: properties}, migrationReceiptTestFragmentDigest,
	); err != nil {
		t.Fatalf("unchanged service generation was rejected: %v", err)
	}
	vendorProperties := migrationReceiptSystemdProperties()
	vendorProperties["FragmentPath"] = migrationLiveReceiptVendorFragment
	if _, err := summarizeMigrationReceiptServiceGenerationWithFragment(
		context.Background(), migrationReceiptSystemdFixture{properties: vendorProperties}, migrationReceiptTestFragmentDigest,
	); err != nil {
		t.Fatalf("trusted /usr/lib CLIProxy service fragment was rejected: %v", err)
	}
	restartDuringSource := migrationReceiptSystemdProperties()
	restartingDigest := func(path string) (string, error) {
		digest, err := migrationReceiptTestFragmentDigest(path)
		restartDuringSource["MainPID"] = "4343"
		restartDuringSource["InvocationID"] = "22222222222242228222222222222222"
		restartDuringSource["ActiveEnterTimestampMonotonic"] = "123999"
		return digest, err
	}
	if _, err := summarizeMigrationReceiptServiceGenerationWithFragment(
		context.Background(), migrationReceiptSystemdFixture{properties: restartDuringSource}, restartingDigest,
	); err == nil {
		t.Fatal("CLIProxy restart while its signed unit source was authenticated was accepted")
	}
	for name, mutate := range map[string]func(map[string]string){
		"stopped": func(value map[string]string) {
			value["ActiveState"], value["SubState"], value["MainPID"] = "inactive", "dead", "0"
		},
		"control pid":   func(value map[string]string) { value["ControlPID"] = "99" },
		"service user":  func(value map[string]string) { value["User"] = "root" },
		"service group": func(value map[string]string) { value["Group"] = "root" },
		"failed result": func(value map[string]string) { value["Result"] = "exit-code" },
		"source drift":  func(value map[string]string) { value["FragmentPath"] = "/run/systemd/system/cliproxyapi.service" },
		"drop-in drift": func(value map[string]string) {
			value["DropInPaths"] = "/run/systemd/system/cliproxyapi.service.d/override.conf"
		},
		"manager cache stale": func(value map[string]string) { value["NeedDaemonReload"] = "yes" },
		"missing invocation":  func(value map[string]string) { delete(value, "InvocationID") },
	} {
		t.Run(name, func(t *testing.T) {
			drifted := migrationReceiptSystemdProperties()
			mutate(drifted)
			if _, err := summarizeMigrationReceiptServiceGenerationWithFragment(
				context.Background(), migrationReceiptSystemdFixture{properties: drifted}, migrationReceiptTestFragmentDigest,
			); err == nil {
				t.Fatal("unsafe CLIProxy service generation was accepted")
			}
		})
	}
	unreachable := errors.New("systemd unavailable")
	if _, err := summarizeMigrationReceiptServiceGenerationWithFragment(
		context.Background(), migrationReceiptSystemdFixture{err: unreachable}, migrationReceiptTestFragmentDigest,
	); !errors.Is(err, unreachable) {
		t.Fatalf("systemd readback failure was not preserved: %v", err)
	}

	restartedProperties := migrationReceiptSystemdProperties()
	restartedProperties["MainPID"] = "4343"
	restartedProperties["InvocationID"] = "22222222222242228222222222222222"
	restartedProperties["ActiveEnterTimestampMonotonic"] = "123999"
	restarted, err := summarizeMigrationReceiptServiceGenerationWithFragment(
		context.Background(), migrationReceiptSystemdFixture{properties: restartedProperties}, migrationReceiptTestFragmentDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	evidence := migrationReceiptTestEvidence()
	receipt := migrationReceiptTestReceipt(t, migrationReceiptTestPath(t), time.Date(2026, 7, 27, 1, 2, 3, 0, time.UTC), evidence, "", "")
	evidence.ServiceGeneration = restarted
	if err := compareMigrationReceiptEvidence(receipt, evidence); err == nil {
		t.Fatal("restarted CLIProxy invocation matched the receipt generation")
	}
	if err := validateMigrationReceiptServiceGenerationWithControllerAndFragment(
		context.Background(), generationSHA256, migrationReceiptSystemdFixture{properties: restartedProperties}, migrationReceiptTestFragmentDigest,
	); err == nil {
		t.Fatal("final generation recheck accepted a restarted CLIProxy invocation")
	}
	changedDigest := func(path string) (string, error) {
		if !migrationReceiptTrustedFragmentPath(path) {
			return "", errors.New("untrusted test fragment")
		}
		return strings.Repeat("8", 64), nil
	}
	if err := validateMigrationReceiptServiceGenerationWithControllerAndFragment(
		context.Background(), generationSHA256, migrationReceiptSystemdFixture{properties: properties}, changedDigest,
	); err == nil {
		t.Fatal("final generation recheck accepted same-path CLIProxy service unit content drift")
	}
}

func TestMigrationReceiptServiceFragmentAuthenticatesSignedAssetAndPathIdentity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned systemd source fixtures require root")
	}
	write := func(t *testing.T, path, payload string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 0, 0); err != nil || os.Chmod(path, mode) != nil {
			t.Fatal("prepare protected systemd source fixture")
		}
	}

	t.Run("matching signed asset", func(t *testing.T) {
		root := t.TempDir()
		installed, reference := filepath.Join(root, "installed.service"), filepath.Join(root, "reference.service")
		const payload = "[Service]\nExecStart=/trusted\n"
		write(t, installed, payload, 0o644)
		write(t, reference, payload, 0o444)
		got, err := summarizeMigrationReceiptServiceFragmentAt(installed, reference)
		if err != nil || got != sha256Hex([]byte(payload)) {
			t.Fatalf("matching signed systemd source rejected: digest=%q err=%v", got, err)
		}
	})

	t.Run("content mismatch", func(t *testing.T) {
		root := t.TempDir()
		installed, reference := filepath.Join(root, "installed.service"), filepath.Join(root, "reference.service")
		write(t, installed, "installed", 0o644)
		write(t, reference, "signed", 0o444)
		if _, err := summarizeMigrationReceiptServiceFragmentAt(installed, reference); err == nil {
			t.Fatal("installed systemd source differing from the signed asset was accepted")
		}
	})

	for name, modes := range map[string]struct {
		installed os.FileMode
		reference os.FileMode
	}{
		"installed mode": {installed: 0o600, reference: 0o444},
		"reference mode": {installed: 0o644, reference: 0o644},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			installed, reference := filepath.Join(root, "installed.service"), filepath.Join(root, "reference.service")
			write(t, installed, "same", modes.installed)
			write(t, reference, "same", modes.reference)
			if _, err := summarizeMigrationReceiptServiceFragmentAt(installed, reference); err == nil {
				t.Fatal("unsafe systemd source mode was accepted")
			}
		})
	}

	t.Run("hardlink", func(t *testing.T) {
		root := t.TempDir()
		installed, alias := filepath.Join(root, "installed.service"), filepath.Join(root, "alias.service")
		write(t, installed, "same", 0o644)
		if err := os.Link(installed, alias); err != nil {
			t.Fatal(err)
		}
		if _, err := readProtectedMigrationReceiptServiceFragmentAt(installed, 0o644, nil); err == nil {
			t.Fatal("multiply-linked systemd source was accepted")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		target, link := filepath.Join(root, "target.service"), filepath.Join(root, "installed.service")
		write(t, target, "same", 0o644)
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := readProtectedMigrationReceiptServiceFragmentAt(link, 0o644, nil); err == nil {
			t.Fatal("linked systemd source was accepted")
		}
	})

	t.Run("acl", func(t *testing.T) {
		root := t.TempDir()
		installed := filepath.Join(root, "installed.service")
		write(t, installed, "same", 0o644)
		file, err := os.OpenFile(installed, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		err = posixacl.SetExclusiveUserPermissionsFD(int(file.Fd()), 12345, 0)
		closeErr := file.Close()
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
			t.Skip("test filesystem does not support POSIX ACLs")
		}
		if err != nil || closeErr != nil {
			t.Fatalf("prepare ACL fixture: %v %v", err, closeErr)
		}
		if err := os.Chmod(installed, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readProtectedMigrationReceiptServiceFragmentAt(installed, 0o644, nil); err == nil {
			t.Fatal("ACL-bearing systemd source was accepted")
		}
	})

	t.Run("pathname replacement", func(t *testing.T) {
		root := t.TempDir()
		installed, replacement := filepath.Join(root, "installed.service"), filepath.Join(root, "replacement.service")
		write(t, installed, "same", 0o644)
		write(t, replacement, "same", 0o644)
		hook := func(point string) error {
			if point != "service-fragment-before-path-recheck" {
				t.Fatalf("unexpected fragment hook %q", point)
			}
			return os.Rename(replacement, installed)
		}
		if _, err := readProtectedMigrationReceiptServiceFragmentAt(installed, 0o644, hook); err == nil {
			t.Fatal("systemd source pathname replacement was accepted")
		}
	})
}

func TestMigrationLiveReceiptPublicationAndRefresh(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned receipt fixture requires root")
	}
	path := migrationReceiptTestPath(t)
	now := time.Date(2026, 7, 27, 1, 2, 3, 4, time.UTC)
	evidence := migrationReceiptTestEvidence()
	first := migrationReceiptTestReceipt(t, path, now, evidence, "", "")
	if err := writeMigrationLiveVerificationReceiptAt(path, first, nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := infoSyscallStat(info)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
		t.Fatalf("published receipt metadata is unsafe: %#v", info)
	}
	if acl, err := migrationReceiptReadACL(int(mustOpenReceiptTestFile(t, path).Fd())); err != nil || len(acl) != 0 {
		t.Fatalf("published receipt inherited an ACL: %x, %v", acl, err)
	}

	second := migrationReceiptTestReceipt(t, path, now.Add(time.Second), evidence, strings.Repeat("6", 64), strings.Repeat("7", 64))
	if err := writeMigrationLiveVerificationReceiptAt(path, second, nil); err != nil {
		t.Fatal(err)
	}
	handle, decoded, payload, err := openMigrationLiveReceipt(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.close()
	defer clear(payload)
	if !reflect.DeepEqual(decoded, second) {
		t.Fatalf("refreshed receipt differs: got %#v want %#v", decoded, second)
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(path), migrationLiveReceiptStageName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful refresh retained its stage: %v", err)
	}
}

func mustOpenReceiptTestFile(t *testing.T, path string) *os.File {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func TestMigrationLiveReceiptRefreshCrashRecovery(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned receipt fixture requires root")
	}
	for _, point := range []string{"stage-linked", "exchanged", "exchange-durable"} {
		t.Run(point, func(t *testing.T) {
			path := migrationReceiptTestPath(t)
			now := time.Date(2026, 7, 27, 1, 2, 3, 0, time.UTC)
			evidence := migrationReceiptTestEvidence()
			first := migrationReceiptTestReceipt(t, path, now, evidence, "", "")
			second := migrationReceiptTestReceipt(t, path, now.Add(time.Second), evidence, strings.Repeat("6", 64), strings.Repeat("7", 64))
			if err := writeMigrationLiveVerificationReceiptAt(path, first, nil); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("simulated crash")
			err := writeMigrationLiveVerificationReceiptAt(path, second, func(actual string) error {
				if actual == point {
					return injected
				}
				return nil
			})
			if !errors.Is(err, injected) {
				t.Fatalf("fault %s was not observed: %v", point, err)
			}
			if _, err := os.Lstat(filepath.Join(filepath.Dir(path), migrationLiveReceiptStageName)); err != nil {
				t.Fatalf("fault %s did not retain a recoverable stage: %v", point, err)
			}
			collectorRan := false
			_, err = validateMigrationLiveVerificationReceiptAt(context.Background(), path, now.Add(2*time.Second), LiveVerificationReceiptValidationOptions{}, func(context.Context, LiveVerificationReceiptValidationOptions) (migrationReceiptBoundEvidence, error) {
				collectorRan = true
				return evidence, nil
			})
			if err == nil || collectorRan {
				t.Fatalf("validator admitted unfinished stage at %s: ran=%v err=%v", point, collectorRan, err)
			}
			if err := writeMigrationLiveVerificationReceiptAt(path, second, nil); err != nil {
				t.Fatalf("recover and repeat refresh after %s: %v", point, err)
			}
			_, decoded, _, err := openMigrationLiveReceipt(path, true)
			if err != nil || !reflect.DeepEqual(decoded, second) {
				t.Fatalf("recovered receipt after %s differs: %#v, %v", point, decoded, err)
			}
		})
	}
}

func TestMigrationLiveReceiptRefusesUnsafeExistingObjects(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned receipt fixture requires root")
	}
	tests := []struct {
		name  string
		setup func(*testing.T, string, []byte)
	}{
		{
			name: "mode",
			setup: func(t *testing.T, path string, payload []byte) {
				if err := os.WriteFile(path, payload, 0o600); err != nil || os.Chmod(path, 0o644) != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T, path string, payload []byte) {
				target := filepath.Join(filepath.Dir(path), "target")
				if err := os.WriteFile(target, payload, 0o600); err != nil || os.Symlink(target, path) != nil {
					t.Fatal("create symlink fixture")
				}
			},
		},
		{
			name: "hardlink",
			setup: func(t *testing.T, path string, payload []byte) {
				target := filepath.Join(filepath.Dir(path), "target")
				if err := os.WriteFile(target, payload, 0o600); err != nil || os.Link(target, path) != nil {
					t.Fatal("create hardlink fixture")
				}
			},
		},
		{
			name: "acl",
			setup: func(t *testing.T, path string, payload []byte) {
				if err := os.WriteFile(path, payload, 0o600); err != nil {
					t.Fatal(err)
				}
				file, err := os.OpenFile(path, os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				if err := posixacl.SetExclusiveUserPermissionsFD(int(file.Fd()), 12345, 0); err != nil {
					file.Close()
					if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
						t.Skip("test filesystem does not support POSIX ACLs")
					}
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "malformed canonical stage",
			setup: func(t *testing.T, path string, payload []byte) {
				if err := os.WriteFile(filepath.Join(filepath.Dir(path), migrationLiveReceiptStageName), []byte("{}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, fixture := range tests {
		t.Run(fixture.name, func(t *testing.T) {
			path := migrationReceiptTestPath(t)
			now := time.Date(2026, 7, 27, 1, 2, 3, 0, time.UTC)
			evidence := migrationReceiptTestEvidence()
			receipt := migrationReceiptTestReceipt(t, path, now, evidence, "", "")
			payload, err := encodeMigrationLiveReceipt(receipt)
			if err != nil {
				t.Fatal(err)
			}
			fixture.setup(t, path, payload)
			beforeFinal, _ := os.ReadFile(path)
			beforeStage, _ := os.ReadFile(filepath.Join(filepath.Dir(path), migrationLiveReceiptStageName))
			if err := writeMigrationLiveVerificationReceiptAt(path, receipt, nil); err == nil {
				t.Fatal("unsafe receipt object was replaced or removed")
			}
			afterFinal, _ := os.ReadFile(path)
			afterStage, _ := os.ReadFile(filepath.Join(filepath.Dir(path), migrationLiveReceiptStageName))
			if !reflect.DeepEqual(beforeFinal, afterFinal) || !reflect.DeepEqual(beforeStage, afterStage) {
				t.Fatal("unsafe object changed on rejected publication")
			}
		})
	}
}

func TestMigrationLiveReceiptRejectsSymlinkedOrNonPrivateParent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned receipt fixture requires root")
	}
	now := time.Date(2026, 7, 27, 1, 2, 3, 0, time.UTC)
	evidence := migrationReceiptTestEvidence()

	root := t.TempDir()
	realParent := filepath.Join(root, "real")
	aliasParent := filepath.Join(root, "alias")
	if err := os.Mkdir(realParent, 0o700); err != nil || os.Symlink(realParent, aliasParent) != nil {
		t.Fatal("create symlinked receipt parent fixture")
	}
	symlinkPath := filepath.Join(aliasParent, migrationLiveReceiptName)
	symlinkReceipt := migrationReceiptTestReceipt(t, symlinkPath, now, evidence, "", "")
	if err := writeMigrationLiveVerificationReceiptAt(symlinkPath, symlinkReceipt, nil); err == nil {
		t.Fatal("symlinked receipt parent was accepted")
	}
	if _, err := os.Lstat(filepath.Join(realParent, migrationLiveReceiptName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlinked receipt parent was modified: %v", err)
	}

	publicParent := filepath.Join(root, "public")
	if err := os.Mkdir(publicParent, 0o700); err != nil || os.Chmod(publicParent, 0o755) != nil {
		t.Fatal("create non-private receipt parent fixture")
	}
	publicPath := filepath.Join(publicParent, migrationLiveReceiptName)
	publicReceipt := migrationReceiptTestReceipt(t, publicPath, now, evidence, "", "")
	if err := writeMigrationLiveVerificationReceiptAt(publicPath, publicReceipt, nil); err == nil {
		t.Fatal("non-private receipt parent was accepted")
	}
}

func TestMigrationLiveReceiptStrictJSONExpiryAndDrift(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned receipt fixture requires root")
	}
	path := migrationReceiptTestPath(t)
	now := time.Date(2026, 7, 27, 1, 2, 3, 0, time.UTC)
	evidence := migrationReceiptTestEvidence()
	receipt := migrationReceiptTestReceipt(t, path, now, evidence, "", "")
	if err := writeMigrationLiveVerificationReceiptAt(path, receipt, nil); err != nil {
		t.Fatal(err)
	}
	collector := func(context.Context, LiveVerificationReceiptValidationOptions) (migrationReceiptBoundEvidence, error) {
		return evidence, nil
	}
	validated, err := validateMigrationLiveVerificationReceiptAt(context.Background(), path, now, LiveVerificationReceiptValidationOptions{}, collector)
	if err != nil || validated.Users != 1 || validated.PendingBundles != 1 || validated.ReceiptSHA256 == "" || validated.ServiceGenerationSHA256 == "" {
		t.Fatalf("valid receipt was rejected: %#v, %v", validated, err)
	}
	if _, err := validateMigrationLiveVerificationReceiptAt(context.Background(), path, now.Add(migrationLiveReceiptTTL), LiveVerificationReceiptValidationOptions{}, collector); err == nil {
		t.Fatal("expired receipt was accepted")
	}
	if _, err := validateMigrationLiveVerificationReceiptAt(context.Background(), path, now.Add(-migrationLiveReceiptClockSkew-time.Nanosecond), LiveVerificationReceiptValidationOptions{}, collector); err == nil {
		t.Fatal("future receipt beyond clock skew was accepted")
	}

	for name, mutate := range map[string]func(*migrationReceiptBoundEvidence){
		"report": func(value *migrationReceiptBoundEvidence) { value.Report.SHA256 = strings.Repeat("8", 64) },
		"plan":   func(value *migrationReceiptBoundEvidence) { value.Plan.SHA256 = strings.Repeat("8", 64) },
		"portal": func(value *migrationReceiptBoundEvidence) {
			value.Portal.IdentityCatalogSHA256 = strings.Repeat("8", 64)
		},
		"pending": func(value *migrationReceiptBoundEvidence) {
			value.PendingBundles[0].BundleSHA256 = strings.Repeat("8", 64)
		},
		"policy":   func(value *migrationReceiptBoundEvidence) { value.PolicyState.SHA256 = strings.Repeat("8", 64) },
		"contract": func(value *migrationReceiptBoundEvidence) { value.InputContract = strings.Repeat("8", 64) },
	} {
		t.Run("drift "+name, func(t *testing.T) {
			drifted := evidence
			drifted.PendingBundles = append([]migrationReceiptPending(nil), evidence.PendingBundles...)
			mutate(&drifted)
			if _, err := validateMigrationLiveVerificationReceiptAt(context.Background(), path, now, LiveVerificationReceiptValidationOptions{}, func(context.Context, LiveVerificationReceiptValidationOptions) (migrationReceiptBoundEvidence, error) {
				return drifted, nil
			}); err == nil {
				t.Fatal("receipt input drift was accepted")
			}
		})
	}

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	canonicalTamper := append([]byte(" "), payload...)
	if err := os.WriteFile(path, canonicalTamper, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateMigrationLiveVerificationReceiptAt(context.Background(), path, now, LiveVerificationReceiptValidationOptions{}, collector); err == nil {
		t.Fatal("non-canonical receipt JSON was accepted")
	}
}

func TestMigrationLiveReceiptRejectsUnknownTrailingAndCanonicalTamper(t *testing.T) {
	path := migrationReceiptTestPath(t)
	now := time.Date(2026, 7, 27, 1, 2, 3, 0, time.UTC)
	evidence := migrationReceiptTestEvidence()
	receipt := migrationReceiptTestReceipt(t, path, now, evidence, "", "")
	payload, err := encodeMigrationLiveReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	unknown := append([]byte(nil), payload[:len(payload)-2]...)
	unknown = append(unknown, []byte(`,"unknown":true}`)...)
	unknown = append(unknown, '\n')
	trailing := append(append([]byte(nil), payload...), []byte("{}\n")...)
	nonCanonical := append([]byte(" "), payload...)
	for name, candidate := range map[string][]byte{"unknown": unknown, "trailing": trailing, "non-canonical": nonCanonical} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeMigrationLiveReceipt(path, candidate); err == nil {
				t.Fatal("invalid receipt JSON was accepted")
			}
		})
	}

	tampered := receipt
	tampered.Report.SHA256 = strings.Repeat("8", 64)
	if _, _, err := validateMigrationLiveReceipt(path, tampered); err == nil {
		t.Fatal("receipt-wide evidence hash omitted report tamper")
	}
	for name, mutate := range map[string]func(*migrationLiveVerificationReceipt){
		"live catalog": func(value *migrationLiveVerificationReceipt) {
			value.CLIProxy.LiveCatalogSHA256 = strings.Repeat("8", 64)
		},
		"live keys":          func(value *migrationLiveVerificationReceipt) { value.CLIProxy.LiveKeysSHA256 = strings.Repeat("8", 64) },
		"service generation": func(value *migrationLiveVerificationReceipt) { value.CLIProxy.ServiceGeneration.MainPID++ },
		"service unit content": func(value *migrationLiveVerificationReceipt) {
			value.CLIProxy.ServiceGeneration.FragmentSHA256 = strings.Repeat("8", 64)
		},
		"evidence digest": func(value *migrationLiveVerificationReceipt) { value.EvidenceSHA256 = strings.Repeat("8", 64) },
	} {
		t.Run("tamper "+name, func(t *testing.T) {
			changed := receipt
			mutate(&changed)
			if _, _, err := validateMigrationLiveReceipt(path, changed); err == nil {
				t.Fatal("receipt canonical field tamper was accepted")
			}
		})
	}
}

func TestMigrationLiveReceiptValidatorDetectsReplacementAndLockFailures(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned receipt fixture requires root")
	}
	path := migrationReceiptTestPath(t)
	now := time.Date(2026, 7, 27, 1, 2, 3, 0, time.UTC)
	evidence := migrationReceiptTestEvidence()
	first := migrationReceiptTestReceipt(t, path, now, evidence, "", "")
	second := migrationReceiptTestReceipt(t, path, now.Add(time.Second), evidence, strings.Repeat("6", 64), strings.Repeat("7", 64))
	if err := writeMigrationLiveVerificationReceiptAt(path, first, nil); err != nil {
		t.Fatal(err)
	}
	_, err := validateMigrationLiveVerificationReceiptAt(context.Background(), path, now.Add(2*time.Second), LiveVerificationReceiptValidationOptions{}, func(context.Context, LiveVerificationReceiptValidationOptions) (migrationReceiptBoundEvidence, error) {
		if err := writeMigrationLiveVerificationReceiptAt(path, second, nil); err != nil {
			return migrationReceiptBoundEvidence{}, err
		}
		return evidence, nil
	})
	if err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("receipt inode replacement during evidence collection was accepted: %v", err)
	}

	collectorRan := false
	lockFailure := errors.New("lock failure")
	_, err = validateMigrationLiveVerificationReceiptWithLock(context.Background(), path, now, LiveVerificationReceiptValidationOptions{}, func() (io.Closer, error) {
		return nil, lockFailure
	}, func(context.Context, LiveVerificationReceiptValidationOptions) (migrationReceiptBoundEvidence, error) {
		collectorRan = true
		return evidence, nil
	})
	if !errors.Is(err, lockFailure) || collectorRan {
		t.Fatalf("migration lock failure did not fail closed: ran=%v err=%v", collectorRan, err)
	}
	_, err = validateMigrationLiveVerificationReceiptWithLock(context.Background(), path, now, LiveVerificationReceiptValidationOptions{}, func() (io.Closer, error) {
		var missing *migrationReceiptTestCloser
		return missing, nil
	}, func(context.Context, LiveVerificationReceiptValidationOptions) (migrationReceiptBoundEvidence, error) {
		collectorRan = true
		return evidence, nil
	})
	if err == nil || collectorRan {
		t.Fatalf("typed-nil migration lock did not fail closed: ran=%v err=%v", collectorRan, err)
	}
}

func TestMigrationLiveReceiptRootOnly(t *testing.T) {
	path := migrationReceiptTestPath(t)
	now := time.Date(2026, 7, 27, 1, 2, 3, 0, time.UTC)
	evidence := migrationReceiptTestEvidence()
	receipt := migrationReceiptTestReceipt(t, path, now, evidence, "", "")
	original := effectiveUID
	effectiveUID = func() int { return 1000 }
	t.Cleanup(func() { effectiveUID = original })
	if err := writeMigrationLiveVerificationReceiptAt(path, receipt, nil); err == nil {
		t.Fatal("non-root receipt publication was accepted")
	}
	collectorRan := false
	if _, err := validateMigrationLiveVerificationReceiptAt(context.Background(), path, now, LiveVerificationReceiptValidationOptions{}, func(context.Context, LiveVerificationReceiptValidationOptions) (migrationReceiptBoundEvidence, error) {
		collectorRan = true
		return evidence, nil
	}); err == nil || collectorRan {
		t.Fatalf("non-root receipt validation was accepted: ran=%v err=%v", collectorRan, err)
	}
	if err := ValidateMigrationLiveVerificationServiceGeneration(context.Background(), strings.Repeat("a", 64)); err == nil {
		t.Fatal("non-root service-generation revalidation was accepted")
	}
}
