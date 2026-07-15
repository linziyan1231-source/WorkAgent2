package userhost

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	_ "modernc.org/sqlite"
)

const (
	workagentBrandingMarkerName    = "workagent-branding-v1.applied"
	workagentBrandingMarkerContent = "assistant=aionui-assistant;brand=WorkAgent AI;skills=v1\n"
)

var workagentSkillFiles = []string{
	filepath.Join("aionui-config", "SKILL.md"),
	filepath.Join("aionui-config", "scripts", "aionui_api.py"),
	filepath.Join("aionui-troubleshooting", "SKILL.md"),
	filepath.Join("aionui-troubleshooting", "scripts", "aion_diag.py"),
	filepath.Join("aionui-webui-public", "SKILL.md"),
	filepath.Join("aionui-webui-setup", "SKILL.md"),
	filepath.Join("aionui-webui-setup", "references", "aionui-webui.md"),
}

//go:embed workagent_assistant_prompt.md
var workagentAssistantPrompt string

func applyWorkAgentBranding(ctx context.Context, dbPath, dataDir, markerPath string, now time.Time) (bool, error) {
	if strings.Contains(workagentAssistantPrompt, "AionUi") || strings.Contains(workagentAssistantPrompt, "AionUI") {
		return false, errors.New("embedded WorkAgent AI assistant prompt contains legacy branding")
	}
	filesChanged, err := brandBuiltinSkillFiles(filepath.Join(dataDir, "builtin-skills"))
	if err != nil {
		return false, err
	}
	info, err := os.Lstat(dbPath)
	if err != nil {
		return false, fmt.Errorf("inspect AionCore database for WorkAgent AI branding: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("AionCore database must be a regular non-symlink file")
	}
	dsn := "file:" + filepath.ToSlash(dbPath) + "?mode=rw&_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return false, fmt.Errorf("open AionCore database for WorkAgent AI branding: %w", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return false, fmt.Errorf("begin WorkAgent AI branding transaction: %w", err)
	}
	defer tx.Rollback()
	if err := validateBrandingSchema(ctx, tx); err != nil {
		return false, err
	}
	assistantChanged, err := brandBuiltinAssistant(ctx, tx, now)
	if err != nil {
		return false, err
	}
	skillsChanged, err := brandSkillDescriptions(ctx, tx, now)
	if err != nil {
		return false, err
	}
	snapshotsChanged, err := brandAssistantSnapshots(ctx, tx, now)
	if err != nil {
		return false, err
	}
	if err := verifyWorkAgentBranding(ctx, tx); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit WorkAgent AI branding: %w", err)
	}
	markerChanged, err := ensureWorkAgentBrandingMarker(markerPath)
	if err != nil {
		return false, err
	}
	return filesChanged || assistantChanged || skillsChanged || snapshotsChanged || markerChanged, nil
}

func validateBrandingSchema(ctx context.Context, tx *sql.Tx) error {
	required := map[string][]string{
		"assistant_definitions":            {"assistant_id", "source", "owner_type", "name", "name_i18n", "description", "description_i18n", "rule_resource_type", "rule_resource_ref", "rule_inline_content", "recommended_prompts", "recommended_prompts_i18n", "updated_at", "deleted_at"},
		"conversation_assistant_snapshots": {"assistant_id", "rules_content", "updated_at"},
		"skills":                           {"name", "description", "source", "updated_at", "deleted_at"},
	}
	for table, columns := range required {
		actual, err := tableColumns(ctx, tx, table)
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

func brandBuiltinAssistant(ctx context.Context, tx *sql.Tx, now time.Time) (bool, error) {
	row := tx.QueryRowContext(ctx, `SELECT name,name_i18n,description,description_i18n,recommended_prompts,recommended_prompts_i18n,
rule_resource_type,rule_resource_ref,rule_inline_content
FROM assistant_definitions
WHERE assistant_id='aionui-assistant' AND source='builtin' AND owner_type='system' AND deleted_at IS NULL`)
	var name, nameI18n, description, descriptionI18n, prompts, promptsI18n, resourceType string
	var resourceRef, inlineContent sql.NullString
	if err := row.Scan(&name, &nameI18n, &description, &descriptionI18n, &prompts, &promptsI18n, &resourceType, &resourceRef, &inlineContent); err != nil {
		return false, fmt.Errorf("read built-in WorkAgent AI assistant: %w", err)
	}
	branded := []string{brandDisplayText(name), brandDisplayText(nameI18n), brandDisplayText(description), brandDisplayText(descriptionI18n), brandDisplayText(prompts), brandDisplayText(promptsI18n)}
	changed := name != branded[0] || nameI18n != branded[1] || description != branded[2] || descriptionI18n != branded[3] || prompts != branded[4] || promptsI18n != branded[5] || resourceType != "inline" || resourceRef.Valid || !inlineContent.Valid || inlineContent.String != workagentAssistantPrompt
	if !changed {
		return false, nil
	}
	result, err := tx.ExecContext(ctx, `UPDATE assistant_definitions SET
name=?,name_i18n=?,description=?,description_i18n=?,recommended_prompts=?,recommended_prompts_i18n=?,
rule_resource_type='inline',rule_resource_ref=NULL,rule_inline_content=?,updated_at=?
WHERE assistant_id='aionui-assistant' AND source='builtin' AND owner_type='system' AND deleted_at IS NULL`,
		branded[0], branded[1], branded[2], branded[3], branded[4], branded[5], workagentAssistantPrompt, now.UnixMilli())
	if err != nil {
		return false, fmt.Errorf("brand built-in WorkAgent AI assistant: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return false, fmt.Errorf("unexpected WorkAgent AI assistant update count: %d (%v)", count, err)
	}
	return true, nil
}

func brandSkillDescriptions(ctx context.Context, tx *sql.Tx, now time.Time) (bool, error) {
	names := []string{"aionui-config", "aionui-troubleshooting", "aionui-webui-public", "aionui-webui-setup"}
	changed := false
	for _, name := range names {
		var description sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT description FROM skills WHERE name=? AND source='builtin' AND deleted_at IS NULL`, name).Scan(&description); err != nil {
			return false, fmt.Errorf("read built-in skill %s: %w", name, err)
		}
		branded := brandDisplayText(description.String)
		if description.Valid && branded != description.String {
			if _, err := tx.ExecContext(ctx, `UPDATE skills SET description=?,updated_at=? WHERE name=? AND source='builtin' AND deleted_at IS NULL`, branded, now.UnixMilli(), name); err != nil {
				return false, fmt.Errorf("brand built-in skill %s: %w", name, err)
			}
			changed = true
		}
	}
	return changed, nil
}

func brandAssistantSnapshots(ctx context.Context, tx *sql.Tx, now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, `UPDATE conversation_assistant_snapshots SET rules_content=?,updated_at=?
WHERE assistant_id='aionui-assistant' AND rules_content<>?`, workagentAssistantPrompt, now.UnixMilli(), workagentAssistantPrompt)
	if err != nil {
		return false, fmt.Errorf("brand existing WorkAgent AI assistant snapshots: %w", err)
	}
	count, err := result.RowsAffected()
	return count > 0, err
}

func verifyWorkAgentBranding(ctx context.Context, tx *sql.Tx) error {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM assistant_definitions
WHERE assistant_id='aionui-assistant' AND source='builtin' AND owner_type='system' AND deleted_at IS NULL
  AND name='WorkAgent AI Butler' AND rule_resource_type='inline' AND rule_resource_ref IS NULL AND rule_inline_content=?
  AND instr(name||name_i18n||description||description_i18n||recommended_prompts||recommended_prompts_i18n||rule_inline_content,'AionUi')=0
  AND instr(name||name_i18n||description||description_i18n||recommended_prompts||recommended_prompts_i18n||rule_inline_content,'AionUI')=0`, workagentAssistantPrompt).Scan(&count); err != nil {
		return fmt.Errorf("verify WorkAgent AI assistant: %w", err)
	}
	if count != 1 {
		return fmt.Errorf("expected exactly one fully branded WorkAgent AI assistant, found %d", count)
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM skills WHERE source='builtin' AND deleted_at IS NULL
AND name IN ('aionui-config','aionui-troubleshooting','aionui-webui-public','aionui-webui-setup')
AND (instr(description,'AionUi')>0 OR instr(description,'AionUI')>0)`).Scan(&count); err != nil {
		return fmt.Errorf("verify WorkAgent AI skill descriptions: %w", err)
	}
	if count != 0 {
		return fmt.Errorf("found %d built-in skill descriptions with legacy branding", count)
	}
	return nil
}

func brandBuiltinSkillFiles(root string) (bool, error) {
	changed := false
	for _, relative := range workagentSkillFiles {
		path := filepath.Join(root, relative)
		info, err := os.Lstat(path)
		if err != nil {
			return false, fmt.Errorf("inspect built-in skill file %s: %w", relative, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("built-in skill file %s must be a regular non-symlink file", relative)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return false, fmt.Errorf("read built-in skill file %s: %w", relative, err)
		}
		branded := brandSkillFileText(string(content))
		if branded == string(content) {
			continue
		}
		if err := replaceFile(path, []byte(branded), info.Mode().Perm()); err != nil {
			return false, fmt.Errorf("brand built-in skill file %s: %w", relative, err)
		}
		changed = true
	}
	return changed, nil
}

func brandSkillFileText(value string) string {
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
	value = brandDisplayText(value)
	for index, literal := range protected {
		value = strings.ReplaceAll(value, fmt.Sprintf("__WORKAGENT_PROTECTED_%d__", index), literal)
	}
	return value
}

func brandDisplayText(value string) string {
	return strings.NewReplacer(
		"AionUi管家", "WorkAgent AI 管家",
		"AionUI管家", "WorkAgent AI 管家",
		"AionUi 管家", "WorkAgent AI 管家",
		"AionUI 管家", "WorkAgent AI 管家",
		"AionUi", "WorkAgent AI",
		"AionUI", "WorkAgent AI",
	).Replace(value)
}

func replaceFile(path string, content []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".workagent-branding.tmp-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(temporaryPath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func ensureWorkAgentBrandingMarker(path string) (bool, error) {
	applied, err := markerHasContent(path, workagentBrandingMarkerContent)
	if err != nil {
		return false, err
	}
	if applied {
		return false, nil
	}
	if err := replaceFile(path, []byte(workagentBrandingMarkerContent), 0o600); err != nil {
		return false, fmt.Errorf("publish WorkAgent AI branding marker: %w", err)
	}
	return true, nil
}
