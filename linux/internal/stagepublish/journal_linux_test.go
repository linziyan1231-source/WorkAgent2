//go:build linux

package stagepublish

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/winmigration"
)

func TestPublicationJournalIsDurableStrictAndStageBound(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	uid := uint32(os.Geteuid())
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.Repeat("a", 64)
	output := strings.Repeat("b", 64)
	tenantID := "11111111-1111-4111-8111-111111111111"
	verified := winmigration.PublicationStage{
		Report:       winmigration.Report{SourceFingerprint: fingerprint, OutputFingerprint: output, Tenants: []winmigration.TenantReport{{TenantID: tenantID, RuntimeUser: "workagent_fixture", ProjectID: 10001, DiskHardLimitBytes: winmigration.TenantDiskLimitBytes}}},
		PortalSHA256: strings.Repeat("c", 64),
		Tenants:      map[string]winmigration.PublicationTenant{tenantID: {Payload: winmigration.PublicationTreeSummary{SHA256: strings.Repeat("d", 64), Files: 1, Bytes: 7}}},
	}
	paths := layout{journalRoot: root, journalPath: filepath.Join(root, "journal.json"), rollbackRoot: filepath.Join(root, "rollback")}
	options := Options{Stage: "/private/stage"}
	value := newJournal(options, verified, paths, time.Unix(123, 0))
	value.Tenants[0].UID, value.Tenants[0].GID = 1234, 1234
	if err := writeJournal(paths.journalPath, &value, uid, time.Unix(124, 0)); err != nil {
		t.Fatal(err)
	}
	loaded, exists, err := loadJournal(paths.journalPath, uid)
	if err != nil || !exists {
		t.Fatalf("load journal: exists=%v err=%v", exists, err)
	}
	if err := loaded.validateAgainst(options, verified, paths); err != nil {
		t.Fatal(err)
	}
	wrong := options
	wrong.Stage = "/private/other-stage"
	if err := loaded.validateAgainst(wrong, verified, paths); err == nil {
		t.Fatal("journal was not bound to its exact stage path")
	}
	if err := os.WriteFile(paths.journalPath, append(mustRead(t, paths.journalPath), []byte(`{"unexpected":true}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadJournal(paths.journalPath, uid); err == nil {
		t.Fatal("journal with trailing JSON was accepted")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
