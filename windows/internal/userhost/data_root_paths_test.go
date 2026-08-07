package userhost

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestRepairLegacyDataRootPathsRebasesPlainAndJSONPaths(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "aionui-backend.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE conversations (name TEXT, extra TEXT);
CREATE TABLE messages (content TEXT);
CREATE TABLE agent_metadata (auth_methods TEXT);
CREATE TABLE teams (workspace TEXT);
CREATE TABLE skills (path TEXT);
INSERT INTO conversations VALUES ('C:\Users\yun\AionUiPortal\workspace\项目', '{"workspace":"C:\\Users\\yun\\AionUiPortal\\workspace\\项目"}');
INSERT INTO messages VALUES ('{"path":"C:\\Users\\yun\\AionUiPortal\\workspace\\out.docx"}');
INSERT INTO agent_metadata VALUES ('[]'); INSERT INTO teams VALUES (NULL); INSERT INTO skills VALUES (NULL);`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	changed, err := repairLegacyDataRootPaths(context.Background(), dbPath, `C:\Users\yun\AionUiPortal`, `E:\AionUiData\users\S-1`)
	if err != nil || changed != 3 {
		t.Fatalf("repair: changed=%d err=%v", changed, err)
	}
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var name, extra, content string
	if err := db.QueryRow(`SELECT name,extra FROM conversations`).Scan(&name, &extra); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT content FROM messages`).Scan(&content); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{name, extra, content} {
		if strings.Contains(value, `C:\Users\yun\AionUiPortal`) {
			t.Fatalf("legacy path remains: %s", value)
		}
	}
	if changed, err := repairLegacyDataRootPaths(context.Background(), dbPath, `C:\Users\yun\AionUiPortal`, `E:\AionUiData\users\S-1`); err != nil || changed != 0 {
		t.Fatalf("repeat repair: changed=%d err=%v", changed, err)
	}
}
