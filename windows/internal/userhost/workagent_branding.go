package userhost

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
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
	workagentBrandingMarkerName    = "workagent-branding-v2.applied"
	workagentBrandingMarkerContent = "assistant=aionui-assistant;brand=WorkAgent;skills=v2;workagent-help=required\n"
)

var workagentAssistantSkillIDs = []string{
	"workagent-help",
	"aionui-config",
	"aionui-troubleshooting",
	"aionui-webui-public",
}

var workagentSkillFiles = []string{
	filepath.Join("aionui-config", "SKILL.md"),
	filepath.Join("aionui-config", "scripts", "aionui_api.py"),
	filepath.Join("aionui-troubleshooting", "SKILL.md"),
	filepath.Join("aionui-troubleshooting", "scripts", "aion_diag.py"),
	filepath.Join("aionui-webui-public", "SKILL.md"),
	filepath.Join("aionui-webui-setup", "SKILL.md"),
	filepath.Join("aionui-webui-setup", "references", "aionui-webui.md"),
}

var workagentHelpFiles = []string{
	filepath.Join("workagent-help", "SKILL.md"),
	filepath.Join("workagent-help", "agents", "openai.yaml"),
	filepath.Join("workagent-help", "references", "help.zh-CN.md"),
}

//go:embed workagent_assistant_prompt.md
var workagentAssistantPrompt string

func applyWorkAgentBranding(ctx context.Context, dbPath, dataDir, markerPath string, now time.Time) (bool, error) {
	if strings.Contains(workagentAssistantPrompt, "AionUi") || strings.Contains(workagentAssistantPrompt, "AionUI") {
		return false, errors.New("embedded WorkAgent assistant prompt contains legacy branding")
	}
	builtinSkillsDir := filepath.Join(dataDir, "builtin-skills")
	if err := validateWorkAgentHelpFiles(builtinSkillsDir); err != nil {
		return false, err
	}
	info, err := os.Lstat(dbPath)
	if err != nil {
		return false, fmt.Errorf("inspect AionCore database for WorkAgent branding: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("AionCore database must be a regular non-symlink file")
	}
	dsn := "file:" + filepath.ToSlash(dbPath) + "?mode=rw&_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return false, fmt.Errorf("open AionCore database for WorkAgent branding: %w", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return false, fmt.Errorf("begin WorkAgent branding transaction: %w", err)
	}
	defer tx.Rollback()
	if err := validateBrandingSchema(ctx, tx); err != nil {
		return false, err
	}
	expectedWorkAgentHelpPath := filepath.Join(builtinSkillsDir, "workagent-help")
	if err := validateWorkAgentHelpRegistration(ctx, tx, expectedWorkAgentHelpPath); err != nil {
		return false, err
	}
	if err := validateWorkAgentSnapshotSkillJSON(ctx, tx); err != nil {
		return false, err
	}
	filesChanged, err := brandBuiltinSkillFiles(builtinSkillsDir)
	if err != nil {
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
	if err := verifyWorkAgentBranding(ctx, tx, expectedWorkAgentHelpPath); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit WorkAgent branding: %w", err)
	}
	markerChanged, err := ensureWorkAgentBrandingMarker(markerPath)
	if err != nil {
		return false, err
	}
	return filesChanged || assistantChanged || skillsChanged || snapshotsChanged || markerChanged, nil
}

func validateBrandingSchema(ctx context.Context, tx *sql.Tx) error {
	required := map[string][]string{
		"assistant_definitions":            {"assistant_id", "source", "owner_type", "name", "name_i18n", "description", "description_i18n", "rule_resource_type", "rule_resource_ref", "rule_inline_content", "recommended_prompts", "recommended_prompts_i18n", "default_skills_mode", "default_skill_ids", "updated_at", "deleted_at"},
		"conversation_assistant_snapshots": {"conversation_id", "assistant_id", "assistant_source", "rules_content", "default_skills_mode", "resolved_skill_ids", "updated_at"},
		"skills":                           {"name", "description", "path", "source", "enabled", "updated_at", "deleted_at"},
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
rule_resource_type,rule_resource_ref,rule_inline_content,default_skills_mode,default_skill_ids
FROM assistant_definitions
WHERE assistant_id='aionui-assistant' AND source='builtin' AND owner_type='system' AND deleted_at IS NULL`)
	var name, nameI18n, description, descriptionI18n, prompts, promptsI18n, resourceType, skillsMode, skillIDs string
	var resourceRef, inlineContent sql.NullString
	if err := row.Scan(&name, &nameI18n, &description, &descriptionI18n, &prompts, &promptsI18n, &resourceType, &resourceRef, &inlineContent, &skillsMode, &skillIDs); err != nil {
		return false, fmt.Errorf("read built-in WorkAgent assistant: %w", err)
	}
	branded := []string{brandDisplayText(name), brandDisplayText(nameI18n), brandDisplayText(description), brandDisplayText(descriptionI18n), brandDisplayText(prompts), brandDisplayText(promptsI18n)}
	canonicalSkillIDs, _ := json.Marshal(workagentAssistantSkillIDs)
	changed := name != branded[0] || nameI18n != branded[1] || description != branded[2] || descriptionI18n != branded[3] || prompts != branded[4] || promptsI18n != branded[5] || resourceType != "inline" || resourceRef.Valid || !inlineContent.Valid || inlineContent.String != workagentAssistantPrompt || skillsMode != "fixed" || skillIDs != string(canonicalSkillIDs)
	if !changed {
		return false, nil
	}
	result, err := tx.ExecContext(ctx, `UPDATE assistant_definitions SET
name=?,name_i18n=?,description=?,description_i18n=?,recommended_prompts=?,recommended_prompts_i18n=?,
rule_resource_type='inline',rule_resource_ref=NULL,rule_inline_content=?,
default_skills_mode='fixed',default_skill_ids=?,updated_at=?
WHERE assistant_id='aionui-assistant' AND source='builtin' AND owner_type='system' AND deleted_at IS NULL`,
		branded[0], branded[1], branded[2], branded[3], branded[4], branded[5], workagentAssistantPrompt, string(canonicalSkillIDs), now.UnixMilli())
	if err != nil {
		return false, fmt.Errorf("brand built-in WorkAgent assistant: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return false, fmt.Errorf("unexpected WorkAgent assistant update count: %d (%v)", count, err)
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
	rows, err := tx.QueryContext(ctx, `SELECT conversation_id,resolved_skill_ids,rules_content,default_skills_mode
FROM conversation_assistant_snapshots
WHERE assistant_id='aionui-assistant' AND assistant_source='builtin'`)
	if err != nil {
		return false, fmt.Errorf("read existing WorkAgent assistant snapshots: %w", err)
	}
	type snapshotUpdate struct {
		conversationID string
		skillIDs       string
	}
	var updates []snapshotUpdate
	for rows.Next() {
		var conversationID, rawSkillIDs, rulesContent, skillsMode string
		if err := rows.Scan(&conversationID, &rawSkillIDs, &rulesContent, &skillsMode); err != nil {
			rows.Close()
			return false, fmt.Errorf("scan existing WorkAgent assistant snapshot: %w", err)
		}
		updatedSkillIDs, err := ensureWorkAgentHelpSkill(rawSkillIDs)
		if err != nil {
			rows.Close()
			return false, fmt.Errorf("normalize WorkAgent assistant snapshot %s skills: %w", conversationID, err)
		}
		if rulesContent != workagentAssistantPrompt || skillsMode != "fixed" || updatedSkillIDs != rawSkillIDs {
			updates = append(updates, snapshotUpdate{conversationID: conversationID, skillIDs: updatedSkillIDs})
		}
	}
	if err := rows.Close(); err != nil {
		return false, fmt.Errorf("close WorkAgent assistant snapshot rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("iterate WorkAgent assistant snapshots: %w", err)
	}
	for _, update := range updates {
		result, err := tx.ExecContext(ctx, `UPDATE conversation_assistant_snapshots
SET rules_content=?,default_skills_mode='fixed',resolved_skill_ids=?,updated_at=?
WHERE conversation_id=? AND assistant_id='aionui-assistant' AND assistant_source='builtin'`,
			workagentAssistantPrompt, update.skillIDs, now.UnixMilli(), update.conversationID)
		if err != nil {
			return false, fmt.Errorf("update WorkAgent assistant snapshot %s: %w", update.conversationID, err)
		}
		if count, err := result.RowsAffected(); err != nil || count != 1 {
			return false, fmt.Errorf("unexpected WorkAgent assistant snapshot %s update count: %d (%v)", update.conversationID, count, err)
		}
	}
	return len(updates) > 0, nil
}

func verifyWorkAgentBranding(ctx context.Context, tx *sql.Tx, expectedWorkAgentHelpPath string) error {
	var count int
	canonicalSkillIDs, _ := json.Marshal(workagentAssistantSkillIDs)
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM assistant_definitions
WHERE assistant_id='aionui-assistant' AND source='builtin' AND owner_type='system' AND deleted_at IS NULL
  AND name='WorkAgent Butler' AND rule_resource_type='inline' AND rule_resource_ref IS NULL AND rule_inline_content=?
  AND default_skills_mode='fixed' AND default_skill_ids=?
  AND instr(name||name_i18n||description||description_i18n||recommended_prompts||recommended_prompts_i18n||rule_inline_content,'AionUi')=0
  AND instr(name||name_i18n||description||description_i18n||recommended_prompts||recommended_prompts_i18n||rule_inline_content,'AionUI')=0`, workagentAssistantPrompt, string(canonicalSkillIDs)).Scan(&count); err != nil {
		return fmt.Errorf("verify WorkAgent assistant: %w", err)
	}
	if count != 1 {
		return fmt.Errorf("expected exactly one fully branded WorkAgent assistant, found %d", count)
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM skills WHERE source='builtin' AND deleted_at IS NULL
AND name IN ('aionui-config','aionui-troubleshooting','aionui-webui-public','aionui-webui-setup')
AND (instr(description,'AionUi')>0 OR instr(description,'AionUI')>0)`).Scan(&count); err != nil {
		return fmt.Errorf("verify WorkAgent skill descriptions: %w", err)
	}
	if count != 0 {
		return fmt.Errorf("found %d built-in skill descriptions with legacy branding", count)
	}
	if err := validateWorkAgentHelpRegistration(ctx, tx, expectedWorkAgentHelpPath); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT conversation_id,resolved_skill_ids,rules_content,default_skills_mode
FROM conversation_assistant_snapshots
WHERE assistant_id='aionui-assistant' AND assistant_source='builtin'`)
	if err != nil {
		return fmt.Errorf("verify WorkAgent assistant snapshots: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var conversationID, rawSkillIDs, rulesContent, skillsMode string
		if err := rows.Scan(&conversationID, &rawSkillIDs, &rulesContent, &skillsMode); err != nil {
			return fmt.Errorf("scan WorkAgent assistant snapshot verification: %w", err)
		}
		var skillIDs []string
		if err := json.Unmarshal([]byte(rawSkillIDs), &skillIDs); err != nil {
			return fmt.Errorf("verify WorkAgent assistant snapshot %s skills: %w", conversationID, err)
		}
		if rulesContent != workagentAssistantPrompt || skillsMode != "fixed" || !containsSkillID(skillIDs, "workagent-help") {
			return fmt.Errorf("WorkAgent assistant snapshot %s is not on the latest prompt and skill binding", conversationID)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate WorkAgent assistant snapshot verification: %w", err)
	}
	return nil
}

func validateWorkAgentHelpRegistration(ctx context.Context, tx *sql.Tx, expectedPath string) error {
	var actualPath string
	if err := tx.QueryRowContext(ctx, `SELECT path FROM skills
WHERE name='workagent-help' AND source='builtin' AND enabled=1 AND deleted_at IS NULL`).Scan(&actualPath); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("expected exactly one enabled built-in workagent-help skill, found 0")
		}
		return fmt.Errorf("verify built-in workagent-help skill: %w", err)
	}
	if !strings.EqualFold(filepath.Clean(actualPath), filepath.Clean(expectedPath)) {
		return fmt.Errorf("built-in workagent-help path %s does not match expected private path %s", actualPath, expectedPath)
	}
	return nil
}

func validateWorkAgentSnapshotSkillJSON(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT conversation_id,resolved_skill_ids
FROM conversation_assistant_snapshots
WHERE assistant_id='aionui-assistant' AND assistant_source='builtin'`)
	if err != nil {
		return fmt.Errorf("preflight WorkAgent assistant snapshots: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var conversationID, rawSkillIDs string
		if err := rows.Scan(&conversationID, &rawSkillIDs); err != nil {
			return fmt.Errorf("scan WorkAgent assistant snapshot preflight: %w", err)
		}
		var skillIDs []string
		if err := json.Unmarshal([]byte(rawSkillIDs), &skillIDs); err != nil {
			return fmt.Errorf("preflight WorkAgent assistant snapshot %s skills: %w", conversationID, err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate WorkAgent assistant snapshot preflight: %w", err)
	}
	return nil
}

func ensureWorkAgentHelpSkill(raw string) (string, error) {
	var current []string
	if err := json.Unmarshal([]byte(raw), &current); err != nil {
		return "", err
	}
	if containsSkillID(current, "workagent-help") {
		return raw, nil
	}
	updated := make([]string, 0, len(current)+1)
	updated = append(updated, "workagent-help")
	updated = append(updated, current...)
	encoded, _ := json.Marshal(updated)
	return string(encoded), nil
}

func containsSkillID(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
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

func validateWorkAgentHelpFiles(root string) error {
	for _, directory := range []string{
		root,
		filepath.Join(root, "workagent-help"),
		filepath.Join(root, "workagent-help", "agents"),
		filepath.Join(root, "workagent-help", "references"),
	} {
		info, err := os.Lstat(directory)
		if err != nil {
			return fmt.Errorf("inspect built-in workagent-help directory %s: %w", directory, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("built-in workagent-help directory %s must be a non-reparse directory", directory)
		}
	}
	for _, relative := range workagentHelpFiles {
		path := filepath.Join(root, relative)
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect built-in workagent-help file %s: %w", relative, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("built-in workagent-help file %s must be a regular non-symlink file", relative)
		}
	}
	return nil
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
		"AionUi管家", "WorkAgent 管家",
		"AionUI管家", "WorkAgent 管家",
		"AionUi 管家", "WorkAgent 管家",
		"AionUI 管家", "WorkAgent 管家",
		"AionUi", "WorkAgent",
		"AionUI", "WorkAgent",
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
	var moveErr error
	for attempt := 0; attempt < 6; attempt++ {
		moveErr = windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
		if moveErr == nil {
			return nil
		}
		if !errors.Is(moveErr, windows.ERROR_ACCESS_DENIED) && !errors.Is(moveErr, windows.ERROR_SHARING_VIOLATION) {
			return moveErr
		}
		time.Sleep(time.Duration(1<<attempt) * 10 * time.Millisecond)
	}
	return moveErr
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
		return false, fmt.Errorf("publish WorkAgent branding marker: %w", err)
	}
	return true, nil
}
