package userhost

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/projectfs"
	_ "modernc.org/sqlite"
)

const (
	workagentBrandingMarkerPath    = "config/workagent-branding-v1.applied"
	workagentBrandingMarkerContent = "assistant=aionui-assistant;brand=WorkAgent2;skills=v1\n"
	workagentAssistantPromptPath   = "workagent-builtin-assistants/rules/aionui-assistant.zh-CN.md"
)

var workagentManagedSkillFiles = []string{
	filepath.Join("data", "builtin-skills", "aionui-config", "SKILL.md"),
	filepath.Join("data", "builtin-skills", "aionui-config", "scripts", "aionui_api.py"),
	filepath.Join("data", "builtin-skills", "aionui-troubleshooting", "SKILL.md"),
	filepath.Join("data", "builtin-skills", "aionui-troubleshooting", "scripts", "aion_diag.py"),
	filepath.Join("data", "builtin-skills", "aionui-webui-public", "SKILL.md"),
	filepath.Join("data", "builtin-skills", "aionui-webui-setup", "SKILL.md"),
	filepath.Join("data", "builtin-skills", "aionui-webui-setup", "references", "aionui-webui.md"),
}

func loadWorkAgentAssistantPrompt(releaseRoot string) ([]byte, error) {
	path := filepath.Join(releaseRoot, filepath.FromSlash(workagentAssistantPromptPath))
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect signed WorkAgent2 assistant prompt: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() <= 0 || info.Size() > 256*1024 {
		return nil, errors.New("signed WorkAgent2 assistant prompt is unsafe")
	}
	prompt, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(prompt) || strings.ContainsRune(string(prompt), 0) || strings.TrimSpace(string(prompt)) == "" || containsLegacyDisplayBrand(string(prompt)) {
		clear(prompt)
		return nil, errors.New("signed WorkAgent2 assistant prompt is empty, invalid, or contains legacy branding")
	}
	return prompt, nil
}

func applyWorkAgentBranding(ctx context.Context, root *projectfs.Root, databaseRelative string, prompt []byte, expectedUID uint32, now time.Time) (bool, error) {
	if root == nil || len(prompt) == 0 || !utf8.Valid(prompt) || containsLegacyDisplayBrand(string(prompt)) {
		return false, errors.New("WorkAgent2 branding input is invalid")
	}
	filesChanged, err := brandWorkAgentManagedSkillFiles(root, expectedUID)
	if err != nil {
		return false, err
	}
	databaseFile, err := root.Open(databaseRelative, unix.O_RDWR|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false, fmt.Errorf("open AionCore database for WorkAgent2 branding: %w", err)
	}
	databaseInfo, statErr := databaseFile.Stat()
	databaseFile.Close()
	if statErr != nil {
		return false, fmt.Errorf("inspect AionCore database for WorkAgent2 branding: %w", statErr)
	}
	databaseStat, ok := databaseInfo.Sys().(*syscall.Stat_t)
	if !ok || databaseStat.Uid != expectedUID || !databaseInfo.Mode().IsRegular() || databaseInfo.Mode().Perm()&0o077 != 0 || databaseInfo.Size() <= 0 || databaseInfo.Size() > 8*1024*1024*1024 {
		return false, errors.New("AionCore database is not a protected tenant-owned regular file")
	}
	dsn := "file:" + filepath.ToSlash(filepath.Join(root.Path(), databaseRelative)) + "?mode=rw&_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return false, fmt.Errorf("open AionCore database for WorkAgent2 branding: %w", err)
	}
	database.SetMaxOpenConns(1)
	defer database.Close()
	transaction, err := database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return false, fmt.Errorf("begin WorkAgent2 branding transaction: %w", err)
	}
	defer transaction.Rollback()
	if err := validateWorkAgentBrandingSchema(ctx, transaction); err != nil {
		return false, err
	}
	assistantChanged, err := brandWorkAgentBuiltinAssistant(ctx, transaction, string(prompt), now)
	if err != nil {
		return false, err
	}
	skillsChanged, err := brandWorkAgentSkillDescriptions(ctx, transaction, now)
	if err != nil {
		return false, err
	}
	snapshotsChanged, err := brandWorkAgentAssistantSnapshots(ctx, transaction, string(prompt), now)
	if err != nil {
		return false, err
	}
	if err := verifyWorkAgentBranding(ctx, transaction, string(prompt)); err != nil {
		return false, err
	}
	if err := transaction.Commit(); err != nil {
		return false, fmt.Errorf("commit WorkAgent2 branding: %w", err)
	}
	markerChanged, err := ensureWorkAgentBrandingMarker(root, expectedUID)
	if err != nil {
		return false, err
	}
	return filesChanged || assistantChanged || skillsChanged || snapshotsChanged || markerChanged, nil
}

func validateWorkAgentBrandingSchema(ctx context.Context, transaction *sql.Tx) error {
	required := map[string][]string{
		"assistant_definitions":            {"assistant_id", "source", "owner_type", "name", "name_i18n", "description", "description_i18n", "rule_resource_type", "rule_resource_ref", "rule_inline_content", "recommended_prompts", "recommended_prompts_i18n", "updated_at", "deleted_at"},
		"conversation_assistant_snapshots": {"assistant_id", "rules_content", "updated_at"},
		"skills":                           {"name", "description", "source", "updated_at", "deleted_at"},
	}
	for table, columns := range required {
		actual, err := brandingTableColumns(ctx, transaction, table)
		if err != nil {
			return err
		}
		for _, column := range columns {
			if !containsColumn(actual, column) {
				return fmt.Errorf("unsupported AionCore %s schema: missing %s", table, column)
			}
		}
	}
	return nil
}

func brandWorkAgentBuiltinAssistant(ctx context.Context, transaction *sql.Tx, prompt string, now time.Time) (bool, error) {
	row := transaction.QueryRowContext(ctx, `SELECT name,name_i18n,description,description_i18n,recommended_prompts,recommended_prompts_i18n,
rule_resource_type,rule_resource_ref,rule_inline_content
FROM assistant_definitions
WHERE assistant_id='aionui-assistant' AND source='builtin' AND owner_type='system' AND deleted_at IS NULL`)
	var name, nameI18n, description, descriptionI18n, prompts, promptsI18n, resourceType string
	var resourceRef, inlineContent sql.NullString
	if err := row.Scan(&name, &nameI18n, &description, &descriptionI18n, &prompts, &promptsI18n, &resourceType, &resourceRef, &inlineContent); err != nil {
		return false, fmt.Errorf("read built-in WorkAgent2 assistant: %w", err)
	}
	branded := []string{workagentBrandDisplayText(name), workagentBrandDisplayText(nameI18n), workagentBrandDisplayText(description), workagentBrandDisplayText(descriptionI18n), workagentBrandDisplayText(prompts), workagentBrandDisplayText(promptsI18n)}
	changed := name != branded[0] || nameI18n != branded[1] || description != branded[2] || descriptionI18n != branded[3] || prompts != branded[4] || promptsI18n != branded[5] || resourceType != "inline" || resourceRef.Valid || !inlineContent.Valid || inlineContent.String != prompt
	if !changed {
		return false, nil
	}
	result, err := transaction.ExecContext(ctx, `UPDATE assistant_definitions SET
name=?,name_i18n=?,description=?,description_i18n=?,recommended_prompts=?,recommended_prompts_i18n=?,
rule_resource_type='inline',rule_resource_ref=NULL,rule_inline_content=?,updated_at=?
WHERE assistant_id='aionui-assistant' AND source='builtin' AND owner_type='system' AND deleted_at IS NULL`,
		branded[0], branded[1], branded[2], branded[3], branded[4], branded[5], prompt, now.UnixMilli())
	if err != nil {
		return false, fmt.Errorf("brand built-in WorkAgent2 assistant: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return false, fmt.Errorf("unexpected WorkAgent2 assistant update count: %d (%v)", count, err)
	}
	return true, nil
}

func brandWorkAgentSkillDescriptions(ctx context.Context, transaction *sql.Tx, now time.Time) (bool, error) {
	changed := false
	for _, name := range []string{"aionui-config", "aionui-troubleshooting", "aionui-webui-public", "aionui-webui-setup"} {
		var description sql.NullString
		if err := transaction.QueryRowContext(ctx, `SELECT description FROM skills WHERE name=? AND source='builtin' AND deleted_at IS NULL`, name).Scan(&description); err != nil {
			return false, fmt.Errorf("read built-in skill %s: %w", name, err)
		}
		branded := workagentBrandDisplayText(description.String)
		if description.Valid && branded != description.String {
			if _, err := transaction.ExecContext(ctx, `UPDATE skills SET description=?,updated_at=? WHERE name=? AND source='builtin' AND deleted_at IS NULL`, branded, now.UnixMilli(), name); err != nil {
				return false, fmt.Errorf("brand built-in skill %s: %w", name, err)
			}
			changed = true
		}
	}
	return changed, nil
}

func brandWorkAgentAssistantSnapshots(ctx context.Context, transaction *sql.Tx, prompt string, now time.Time) (bool, error) {
	result, err := transaction.ExecContext(ctx, `UPDATE conversation_assistant_snapshots SET rules_content=?,updated_at=?
WHERE assistant_id='aionui-assistant' AND rules_content<>?`, prompt, now.UnixMilli(), prompt)
	if err != nil {
		return false, fmt.Errorf("brand WorkAgent2 assistant snapshots: %w", err)
	}
	count, err := result.RowsAffected()
	return count > 0, err
}

func verifyWorkAgentBranding(ctx context.Context, transaction *sql.Tx, prompt string) error {
	var count int
	if err := transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM assistant_definitions
WHERE assistant_id='aionui-assistant' AND source='builtin' AND owner_type='system' AND deleted_at IS NULL
  AND rule_resource_type='inline' AND rule_resource_ref IS NULL AND rule_inline_content=?
  AND instr(COALESCE(name,'')||COALESCE(name_i18n,'')||COALESCE(description,'')||COALESCE(description_i18n,'')||COALESCE(recommended_prompts,'')||COALESCE(recommended_prompts_i18n,''),'AionUi')=0
  AND instr(COALESCE(name,'')||COALESCE(name_i18n,'')||COALESCE(description,'')||COALESCE(description_i18n,'')||COALESCE(recommended_prompts,'')||COALESCE(recommended_prompts_i18n,''),'AionUI')=0
	AND instr(COALESCE(name,'')||COALESCE(name_i18n,'')||COALESCE(description,'')||COALESCE(description_i18n,'')||COALESCE(recommended_prompts,'')||COALESCE(recommended_prompts_i18n,''),'WorkAgent2')=0
	AND instr(COALESCE(name,'')||COALESCE(name_i18n,'')||COALESCE(description,'')||COALESCE(description_i18n,'')||COALESCE(recommended_prompts,'')||COALESCE(recommended_prompts_i18n,''),'WorkAgent2')>0`, prompt).Scan(&count); err != nil {
		return fmt.Errorf("verify WorkAgent2 assistant: %w", err)
	}
	if count != 1 {
		return fmt.Errorf("expected exactly one fully branded WorkAgent2 assistant, found %d", count)
	}
	if err := transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM skills WHERE source='builtin' AND deleted_at IS NULL
AND name IN ('aionui-config','aionui-troubleshooting','aionui-webui-public','aionui-webui-setup')
AND (instr(COALESCE(description,''),'AionUi')>0 OR instr(COALESCE(description,''),'AionUI')>0 OR instr(COALESCE(description,''),'WorkAgent2')>0)`).Scan(&count); err != nil {
		return fmt.Errorf("verify WorkAgent2 skill descriptions: %w", err)
	}
	if count != 0 {
		return fmt.Errorf("found %d built-in skill descriptions with legacy branding", count)
	}
	if err := transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM conversation_assistant_snapshots WHERE assistant_id='aionui-assistant' AND rules_content<>?`, prompt).Scan(&count); err != nil {
		return fmt.Errorf("verify WorkAgent2 assistant snapshots: %w", err)
	}
	if count != 0 {
		return fmt.Errorf("found %d assistant snapshots with stale branding", count)
	}
	return nil
}

func brandWorkAgentManagedSkillFiles(root *projectfs.Root, expectedUID uint32) (bool, error) {
	changed := false
	for _, relative := range workagentManagedSkillFiles {
		file, err := root.Open(relative, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return false, fmt.Errorf("inspect built-in skill file %s: %w", relative, err)
		}
		info, statErr := file.Stat()
		if statErr != nil {
			file.Close()
			return false, fmt.Errorf("inspect built-in skill file %s: %w", relative, statErr)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != expectedUID || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 2*1024*1024 {
			file.Close()
			return false, fmt.Errorf("built-in skill file %s is unsafe", relative)
		}
		content, readErr := io.ReadAll(io.LimitReader(file, 2*1024*1024+1))
		file.Close()
		if readErr != nil || len(content) > 2*1024*1024 || !utf8.Valid(content) {
			clear(content)
			return false, fmt.Errorf("read built-in skill file %s", relative)
		}
		branded := []byte(workagentBrandSkillFileText(string(content)))
		if string(branded) != string(content) {
			if err := root.WriteFileAtomic(relative, branded, 0o600); err != nil {
				clear(content)
				clear(branded)
				return false, fmt.Errorf("brand built-in skill file %s: %w", relative, err)
			}
			changed = true
		}
		clear(content)
		clear(branded)
	}
	return changed, nil
}

func workagentBrandSkillFileText(value string) string {
	protected := []string{
		"https://github.com/iOfficeAI/AionUi",
		"/Applications/AionUi.app/Contents/MacOS/AionUi",
		"%APPDATA%/AionUi",
		"~/Library/Application Support/AionUi",
		"~/.config/AionUi",
		"~/Library/Logs/AionUi",
		"ps aux | grep AionUi",
	}
	for index, literal := range protected {
		value = strings.ReplaceAll(value, literal, fmt.Sprintf("__WORKAGENT_PROTECTED_%d__", index))
	}
	value = workagentBrandDisplayText(value)
	for index, literal := range protected {
		value = strings.ReplaceAll(value, fmt.Sprintf("__WORKAGENT_PROTECTED_%d__", index), literal)
	}
	return value
}

func workagentBrandDisplayText(value string) string {
	return strings.NewReplacer(
		"WorkAgent2 管家", "WorkAgent2 管家",
		"WorkAgent2 Butler", "WorkAgent2 Butler",
		"WorkAgent2", "WorkAgent2",
		"AionUi管家", "WorkAgent2 管家",
		"AionUI管家", "WorkAgent2 管家",
		"AionUi 管家", "WorkAgent2 管家",
		"AionUI 管家", "WorkAgent2 管家",
		"AionUi", "WorkAgent2",
		"AionUI", "WorkAgent2",
	).Replace(value)
}

func containsLegacyDisplayBrand(value string) bool {
	return strings.Contains(value, "AionUi") || strings.Contains(value, "AionUI") || strings.Contains(strings.ToLower(value), "workagent ai")
}

func ensureWorkAgentBrandingMarker(root *projectfs.Root, expectedUID uint32) (bool, error) {
	file, err := root.Open(workagentBrandingMarkerPath, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err == nil {
		info, statErr := file.Stat()
		if statErr != nil {
			file.Close()
			return false, fmt.Errorf("inspect WorkAgent2 branding marker: %w", statErr)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		payload, readErr := io.ReadAll(io.LimitReader(file, 4097))
		file.Close()
		if !ok || stat.Uid != expectedUID || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > 4096 || readErr != nil || string(payload) != workagentBrandingMarkerContent {
			clear(payload)
			return false, errors.New("WorkAgent2 branding marker is unsafe or has unexpected content")
		}
		clear(payload)
		return false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect WorkAgent2 branding marker: %w", err)
	}
	if err := root.WriteFileAtomic(workagentBrandingMarkerPath, []byte(workagentBrandingMarkerContent), 0o600); err != nil {
		return false, fmt.Errorf("write WorkAgent2 branding marker: %w", err)
	}
	return true, nil
}

func brandingTableColumns(ctx context.Context, transaction *sql.Tx, table string) ([]string, error) {
	switch table {
	case "assistant_definitions", "conversation_assistant_snapshots", "skills":
	default:
		return nil, errors.New("unsupported WorkAgent2 branding table")
	}
	rows, err := transaction.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var position, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&position, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	return columns, rows.Err()
}
