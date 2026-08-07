package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrConflict             = errors.New("conflict")
	ErrExpired              = errors.New("expired")
	ErrInviteAlreadyPending = errors.New("shared invite already pending")
	ErrSharedAlreadyMember  = errors.New("shared project member already exists")
)

type SharedProject struct {
	ID          string
	OwnerUserID int64
	OwnerSID    string
	OwnerName   string
	Name        string
	SourceKind  string
	State       string
	CurrentRole string
	MemberCount int
	Hidden      bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type SharedMember struct {
	UserID      int64
	Username    string
	DisplayName string
	WindowsSID  string
	Role        string
	JoinedAt    time.Time
}

type SharedInvite struct {
	ID               string
	ProjectID        string
	ProjectName      string
	InviterUserID    int64
	InviterName      string
	TargetUserID     int64
	TargetName       string
	TargetWindowsSID string
	Status           string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	ActedAt          *time.Time
}

type SharedInviteLink struct {
	Token         string
	ProjectID     string
	InviterUserID int64
	ExpiresAt     time.Time
}

type SharedConversation struct {
	ID                    string
	ProjectID             string
	ProjectName           string
	CurrentRole           string
	Name                  string
	AssistantID           string
	AssistantBackend      string
	ModelID               string
	ThinkingEffort        string
	RuntimeConversationID string
	RuntimeOwnerUserID    int64
	State                 string
	LastAIMessageSeq      int64
	Pinned                bool
	PinnedAt              *time.Time
	Hidden                bool
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

type SharedMention struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type SharedMessage struct {
	Seq          int64
	ID           string
	Conversation string
	AuthorUserID *int64
	AuthorName   string
	AuthorAvatar string
	Kind         string
	Body         string
	Mentions     []SharedMention
	Attachments  []string
	CreatedAt    time.Time
}

type SharedAIRunPayer struct {
	UserID int64
	KeyID  string
}

type SharedAIRun struct {
	ID                string
	ConversationID    string
	TriggerMessageID  string
	Provider          string
	OwnerUserID       int64
	ContextFromSeq    int64
	ContextThroughSeq int64
}

func NewStableID() (string, error) {
	random := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(random), nil
}

func (s *Store) SearchSharedUsers(ctx context.Context, requesterID int64, query string, limit int) ([]User, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return []User{}, nil
	}
	if utf8.RuneCountInString(query) > 64 {
		return nil, errors.New("shared user query is too long")
	}
	for _, character := range query {
		if unicode.IsControl(character) {
			return nil, errors.New("shared user query is invalid")
		}
	}
	if limit < 1 || limit > 50 {
		limit = 20
	}
	pattern := "%" + escapeSharedLike(strings.ToLower(query)) + "%"
	rows, err := s.db.QueryContext(ctx, userSelect+` WHERE id<>? AND enabled=1 AND is_admin=0 AND (lower(username) LIKE ? ESCAPE '\' OR lower(display_name) LIKE ? ESCAPE '\') ORDER BY username_norm LIMIT ?`, requesterID, pattern, pattern, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, user)
	}
	return result, rows.Err()
}

func escapeSharedLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	return strings.ReplaceAll(value, `_`, `\_`)
}

func (s *Store) CreateSharedProject(ctx context.Context, project SharedProject, now time.Time) (SharedProject, error) {
	project.ID = strings.TrimSpace(project.ID)
	project.Name = strings.TrimSpace(project.Name)
	if len(project.ID) != 32 || project.OwnerUserID <= 0 || project.Name == "" || len(project.Name) > 128 {
		return SharedProject{}, errors.New("shared project identity, owner, and bounded name are required")
	}
	if project.SourceKind != "new" && project.SourceKind != "copy" && project.SourceKind != "migrate" {
		return SharedProject{}, errors.New("shared project source kind is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SharedProject{}, err
	}
	defer tx.Rollback()
	stamp := now.Unix()
	if _, err := tx.ExecContext(ctx, `INSERT INTO shared_projects(id,owner_user_id,name,source_kind,state,created_at,updated_at) VALUES(?,?,?,?, 'provisioning',?,?)`, project.ID, project.OwnerUserID, project.Name, project.SourceKind, stamp, stamp); err != nil {
		return SharedProject{}, fmt.Errorf("create shared project: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO shared_project_members(project_id,user_id,role,state,joined_at) VALUES(?,?,'owner','accepted',?)`, project.ID, project.OwnerUserID, stamp); err != nil {
		return SharedProject{}, fmt.Errorf("create shared project owner: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return SharedProject{}, err
	}
	return s.SharedProjectForUser(ctx, project.ID, project.OwnerUserID, true)
}

func (s *Store) SetSharedProjectProvisioningResult(ctx context.Context, projectID string, active bool, now time.Time) error {
	state := "failed"
	if active {
		state = "active"
	}
	result, err := s.db.ExecContext(ctx, `UPDATE shared_projects SET state=?,updated_at=? WHERE id=? AND state='provisioning'`, state, now.Unix(), strings.TrimSpace(projectID))
	if err != nil {
		return err
	}
	return requireChanged(result)
}

func (s *Store) RevertSharedProjectActivation(ctx context.Context, projectID string, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE shared_projects SET state='provisioning',updated_at=? WHERE id=? AND state='active'`, now.Unix(), strings.TrimSpace(projectID))
	if err != nil {
		return err
	}
	return requireChanged(result)
}

func (s *Store) AbortSharedProjectProvisioning(ctx context.Context, projectID string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM shared_projects WHERE id=? AND state IN ('provisioning','failed')`, strings.TrimSpace(projectID))
	if err != nil {
		return err
	}
	return requireChanged(result)
}

func (s *Store) SharedOwnerRootMemberSIDs(ctx context.Context, ownerUserID int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT u.windows_sid FROM shared_projects p JOIN shared_project_members m ON m.project_id=p.id JOIN portal_users u ON u.id=m.user_id WHERE p.owner_user_id=? AND m.user_id<>p.owner_user_id AND p.state IN ('provisioning','active','transfer_pending') AND m.state IN ('pending_acl','accepted') ORDER BY upper(u.windows_sid)`, ownerUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var sid string
		if err := rows.Scan(&sid); err != nil {
			return nil, err
		}
		result = append(result, sid)
	}
	return result, rows.Err()
}

func (s *Store) SharedProjectACLSIDs(ctx context.Context, projectID string, ownerUserID int64) ([]string, error) {
	var owner int64
	if err := s.db.QueryRowContext(ctx, `SELECT owner_user_id FROM shared_projects WHERE id=? AND state IN ('active','transfer_pending')`, projectID).Scan(&owner); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if owner != ownerUserID {
		return nil, ErrForbidden
	}
	rows, err := s.db.QueryContext(ctx, `SELECT u.windows_sid FROM shared_project_members m JOIN portal_users u ON u.id=m.user_id WHERE m.project_id=? AND m.user_id<>? AND m.state IN ('pending_acl','accepted') ORDER BY upper(u.windows_sid)`, projectID, ownerUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var sid string
		if err := rows.Scan(&sid); err != nil {
			return nil, err
		}
		result = append(result, sid)
	}
	return result, rows.Err()
}

func (s *Store) SharedProjectForUser(ctx context.Context, projectID string, userID int64, includeHidden bool) (SharedProject, error) {
	query := `SELECT p.id,p.owner_user_id,owner.windows_sid,owner.display_name,p.name,p.source_kind,p.state,m.role,
	 (SELECT COUNT(*) FROM shared_project_members x WHERE x.project_id=p.id AND x.state='accepted'),
	 EXISTS(SELECT 1 FROM shared_hidden_items h WHERE h.user_id=? AND h.item_kind='project' AND h.item_id=p.id),p.created_at,p.updated_at
	 FROM shared_projects p JOIN shared_project_members m ON m.project_id=p.id AND m.user_id=? AND m.state='accepted'
	 JOIN portal_users owner ON owner.id=p.owner_user_id WHERE p.id=?`
	var out SharedProject
	var hidden int
	var created, updated int64
	err := s.db.QueryRowContext(ctx, query, userID, userID, strings.TrimSpace(projectID)).Scan(&out.ID, &out.OwnerUserID, &out.OwnerSID, &out.OwnerName, &out.Name, &out.SourceKind, &out.State, &out.CurrentRole, &out.MemberCount, &hidden, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return SharedProject{}, ErrNotFound
	}
	if err != nil {
		return SharedProject{}, err
	}
	out.Hidden = hidden != 0
	if out.Hidden && !includeHidden {
		return SharedProject{}, ErrNotFound
	}
	out.CreatedAt, out.UpdatedAt = time.Unix(created, 0).UTC(), time.Unix(updated, 0).UTC()
	return out, nil
}

func (s *Store) ListSharedProjects(ctx context.Context, userID int64, includeHidden bool) ([]SharedProject, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT p.id FROM shared_projects p JOIN shared_project_members m ON m.project_id=p.id AND m.user_id=? AND m.state='accepted'
	 WHERE ? OR NOT EXISTS(SELECT 1 FROM shared_hidden_items h WHERE h.user_id=? AND h.item_kind='project' AND h.item_id=p.id)
	 ORDER BY p.updated_at DESC,p.id`, userID, boolInt(includeHidden), userID)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	// The Portal store intentionally uses a single SQLite connection. Release
	// the list query before loading project details or the nested query waits on
	// the connection held by rows and deadlocks as soon as a project exists.
	result := make([]SharedProject, 0, len(ids))
	for _, id := range ids {
		project, err := s.SharedProjectForUser(ctx, id, userID, includeHidden)
		if err != nil {
			return nil, err
		}
		result = append(result, project)
	}
	return result, nil
}

func (s *Store) SharedProjectMembers(ctx context.Context, projectID string, requesterID int64) ([]SharedMember, error) {
	if _, err := s.SharedProjectForUser(ctx, projectID, requesterID, true); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT u.id,u.username,u.display_name,u.windows_sid,m.role,m.joined_at FROM shared_project_members m JOIN portal_users u ON u.id=m.user_id WHERE m.project_id=? AND m.state='accepted' ORDER BY CASE m.role WHEN 'owner' THEN 0 ELSE 1 END,u.username_norm`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []SharedMember
	for rows.Next() {
		var item SharedMember
		var joined int64
		if err := rows.Scan(&item.UserID, &item.Username, &item.DisplayName, &item.WindowsSID, &item.Role, &joined); err != nil {
			return nil, err
		}
		item.JoinedAt = time.Unix(joined, 0).UTC()
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) BeginSharedOwnershipTransfer(ctx context.Context, projectID string, targetUserID, ownerUserID int64, now time.Time) (SharedProject, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SharedProject{}, err
	}
	defer tx.Rollback()
	var actualOwner int64
	var state string
	if err := tx.QueryRowContext(ctx, `SELECT owner_user_id,state FROM shared_projects WHERE id=?`, strings.TrimSpace(projectID)).Scan(&actualOwner, &state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SharedProject{}, ErrNotFound
		}
		return SharedProject{}, err
	}
	if actualOwner != ownerUserID || targetUserID <= 0 || targetUserID == ownerUserID || state != "active" {
		return SharedProject{}, ErrForbidden
	}
	var accepted int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM shared_project_members WHERE project_id=? AND user_id=? AND role='member' AND state='accepted'`, projectID, targetUserID).Scan(&accepted); err != nil {
		return SharedProject{}, err
	}
	if accepted != 1 {
		return SharedProject{}, ErrForbidden
	}
	var running int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM shared_conversations WHERE project_id=? AND state<>'idle'`, projectID).Scan(&running); err != nil {
		return SharedProject{}, err
	}
	if running != 0 {
		return SharedProject{}, ErrConflict
	}
	result, err := tx.ExecContext(ctx, `UPDATE shared_projects SET state='transfer_pending',updated_at=? WHERE id=? AND owner_user_id=? AND state='active'`, now.Unix(), projectID, ownerUserID)
	if err != nil {
		return SharedProject{}, err
	}
	if err := requireChanged(result); err != nil {
		return SharedProject{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return SharedProject{}, err
	}
	return s.SharedProjectForUser(ctx, projectID, ownerUserID, true)
}

func (s *Store) FinishSharedOwnershipTransfer(ctx context.Context, projectID string, oldOwnerUserID, newOwnerUserID int64, success bool, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var owner int64
	if err := tx.QueryRowContext(ctx, `SELECT owner_user_id FROM shared_projects WHERE id=? AND state='transfer_pending'`, projectID).Scan(&owner); err != nil {
		return err
	}
	if owner != oldOwnerUserID {
		return ErrConflict
	}
	if !success {
		result, err := tx.ExecContext(ctx, `UPDATE shared_projects SET state='active',updated_at=? WHERE id=? AND state='transfer_pending'`, now.Unix(), projectID)
		if err != nil {
			return err
		}
		if err := requireChanged(result); err != nil {
			return err
		}
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `UPDATE shared_project_members SET role='member' WHERE project_id=? AND user_id=? AND role='owner' AND state='accepted'`, projectID, oldOwnerUserID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE shared_project_members SET role='owner' WHERE project_id=? AND user_id=? AND role='member' AND state='accepted'`, projectID, newOwnerUserID)
	if err != nil {
		return err
	}
	if err := requireChanged(result); err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `UPDATE shared_projects SET owner_user_id=?,state='active',updated_at=? WHERE id=? AND owner_user_id=? AND state='transfer_pending'`, newOwnerUserID, now.Unix(), projectID, oldOwnerUserID)
	if err != nil {
		return err
	}
	if err := requireChanged(result); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE shared_conversations SET runtime_owner_user_id=?,runtime_conversation_id=NULL,state='idle',updated_at=? WHERE project_id=?`, newOwnerUserID, now.Unix(), projectID); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM shared_conversations WHERE project_id=?`, projectID)
	if err != nil {
		return err
	}
	var conversationIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		conversationIDs = append(conversationIDs, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, conversationID := range conversationIDs {
		id, err := NewStableID()
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO shared_messages(id,conversation_id,kind,body,created_at) VALUES(?,?,'system',?,?)`, id, conversationID, "Project ownership was transferred. The next AI request will rebuild its runtime from shared history under the new owner.", now.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) BeginRemoveSharedMember(ctx context.Context, projectID string, targetUserID, requesterUserID int64, now time.Time) (SharedProject, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SharedProject{}, err
	}
	defer tx.Rollback()
	var ownerUserID int64
	var state string
	if err := tx.QueryRowContext(ctx, `SELECT owner_user_id,state FROM shared_projects WHERE id=?`, strings.TrimSpace(projectID)).Scan(&ownerUserID, &state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SharedProject{}, ErrNotFound
		}
		return SharedProject{}, err
	}
	if state != "active" || targetUserID <= 0 || targetUserID == ownerUserID || (requesterUserID != ownerUserID && requesterUserID != targetUserID) {
		return SharedProject{}, ErrForbidden
	}
	result, err := tx.ExecContext(ctx, `UPDATE shared_project_members SET state='removing' WHERE project_id=? AND user_id=? AND role='member' AND state='accepted'`, projectID, targetUserID)
	if err != nil {
		return SharedProject{}, err
	}
	if err := requireChanged(result); err != nil {
		return SharedProject{}, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `UPDATE shared_projects SET updated_at=? WHERE id=?`, now.Unix(), projectID); err != nil {
		return SharedProject{}, err
	}
	if err := tx.Commit(); err != nil {
		return SharedProject{}, err
	}
	return s.SharedProjectForUser(ctx, projectID, ownerUserID, true)
}

func (s *Store) FinishRemoveSharedMember(ctx context.Context, projectID string, targetUserID int64, success bool, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var result sql.Result
	if success {
		result, err = tx.ExecContext(ctx, `DELETE FROM shared_project_members WHERE project_id=? AND user_id=? AND role='member' AND state='removing'`, projectID, targetUserID)
	} else {
		result, err = tx.ExecContext(ctx, `UPDATE shared_project_members SET state='accepted' WHERE project_id=? AND user_id=? AND role='member' AND state='removing'`, projectID, targetUserID)
	}
	if err != nil {
		return err
	}
	if err := requireChanged(result); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE shared_projects SET updated_at=? WHERE id=?`, now.Unix(), projectID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CreateSharedInvite(ctx context.Context, invite SharedInvite, ownerUserID int64, now time.Time) (SharedInvite, error) {
	invite.ID = strings.TrimSpace(invite.ID)
	if len(invite.ID) != 32 || invite.ProjectID == "" || invite.TargetUserID <= 0 || invite.TargetUserID == ownerUserID || !invite.ExpiresAt.After(now) {
		return SharedInvite{}, errors.New("shared invite fields are invalid")
	}
	project, err := s.SharedProjectForUser(ctx, invite.ProjectID, ownerUserID, true)
	if err != nil || project.CurrentRole != "owner" || project.State != "active" {
		return SharedInvite{}, ErrForbidden
	}
	var enabled, alreadyMember, pendingInvite int
	err = s.db.QueryRowContext(ctx, `SELECT u.enabled,EXISTS(SELECT 1 FROM shared_project_members m WHERE m.project_id=? AND m.user_id=u.id AND m.state IN ('pending_acl','accepted')),EXISTS(SELECT 1 FROM shared_project_invites i WHERE i.project_id=? AND i.target_user_id=u.id AND i.status='pending') FROM portal_users u WHERE u.id=? AND u.is_admin=0`, invite.ProjectID, invite.ProjectID, invite.TargetUserID).Scan(&enabled, &alreadyMember, &pendingInvite)
	if errors.Is(err, sql.ErrNoRows) {
		return SharedInvite{}, ErrNotFound
	}
	if err != nil {
		return SharedInvite{}, err
	}
	if enabled == 0 {
		return SharedInvite{}, ErrForbidden
	}
	if alreadyMember != 0 {
		return SharedInvite{}, ErrSharedAlreadyMember
	}
	if pendingInvite != 0 {
		return SharedInvite{}, ErrInviteAlreadyPending
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO shared_project_invites(id,project_id,inviter_user_id,target_user_id,status,created_at,expires_at) VALUES(?,?,?,?,'pending',?,?)`, invite.ID, invite.ProjectID, ownerUserID, invite.TargetUserID, now.Unix(), invite.ExpiresAt.Unix())
	if err != nil {
		var exists int
		if queryErr := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM shared_project_invites WHERE project_id=? AND target_user_id=? AND status='pending')`, invite.ProjectID, invite.TargetUserID).Scan(&exists); queryErr == nil && exists != 0 {
			return SharedInvite{}, ErrInviteAlreadyPending
		}
		return SharedInvite{}, fmt.Errorf("create shared invite: %w", err)
	}
	return s.SharedInviteForUser(ctx, invite.ID, ownerUserID)
}

func (s *Store) SharedInviteForUser(ctx context.Context, inviteID string, userID int64) (SharedInvite, error) {
	var out SharedInvite
	var created, expires int64
	var acted sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT i.id,i.project_id,p.name,i.inviter_user_id,inviter.display_name,i.target_user_id,target.display_name,target.windows_sid,i.status,i.created_at,i.expires_at,i.acted_at FROM shared_project_invites i JOIN shared_projects p ON p.id=i.project_id JOIN portal_users inviter ON inviter.id=i.inviter_user_id JOIN portal_users target ON target.id=i.target_user_id WHERE i.id=? AND (i.inviter_user_id=? OR i.target_user_id=?)`, strings.TrimSpace(inviteID), userID, userID).Scan(&out.ID, &out.ProjectID, &out.ProjectName, &out.InviterUserID, &out.InviterName, &out.TargetUserID, &out.TargetName, &out.TargetWindowsSID, &out.Status, &created, &expires, &acted)
	if errors.Is(err, sql.ErrNoRows) {
		return SharedInvite{}, ErrNotFound
	}
	if err != nil {
		return SharedInvite{}, err
	}
	out.CreatedAt, out.ExpiresAt = time.Unix(created, 0).UTC(), time.Unix(expires, 0).UTC()
	if acted.Valid {
		value := time.Unix(acted.Int64, 0).UTC()
		out.ActedAt = &value
	}
	return out, nil
}

func (s *Store) ListPendingSharedInvites(ctx context.Context, targetUserID int64, now time.Time) ([]SharedInvite, error) {
	if targetUserID <= 0 {
		return nil, errors.New("shared invite target is invalid")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE shared_project_invites SET status='expired',acted_at=? WHERE target_user_id=? AND status='pending' AND expires_at<=?`, now.Unix(), targetUserID, now.Unix()); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT i.id,i.project_id,p.name,i.inviter_user_id,inviter.display_name,i.target_user_id,target.display_name,target.windows_sid,i.status,i.created_at,i.expires_at,i.acted_at FROM shared_project_invites i JOIN shared_projects p ON p.id=i.project_id JOIN portal_users inviter ON inviter.id=i.inviter_user_id JOIN portal_users target ON target.id=i.target_user_id WHERE i.target_user_id=? AND i.status='pending' ORDER BY i.created_at DESC,i.id`, targetUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []SharedInvite
	for rows.Next() {
		var item SharedInvite
		var created, expires int64
		var acted sql.NullInt64
		if err := rows.Scan(&item.ID, &item.ProjectID, &item.ProjectName, &item.InviterUserID, &item.InviterName, &item.TargetUserID, &item.TargetName, &item.TargetWindowsSID, &item.Status, &created, &expires, &acted); err != nil {
			return nil, err
		}
		item.CreatedAt, item.ExpiresAt = time.Unix(created, 0).UTC(), time.Unix(expires, 0).UTC()
		if acted.Valid {
			value := time.Unix(acted.Int64, 0).UTC()
			item.ActedAt = &value
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) BeginAcceptSharedInvite(ctx context.Context, inviteID string, targetUserID int64, now time.Time) (SharedInvite, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SharedInvite{}, err
	}
	defer tx.Rollback()
	var projectID string
	var expires int64
	var status string
	err = tx.QueryRowContext(ctx, `SELECT project_id,expires_at,status FROM shared_project_invites WHERE id=? AND target_user_id=?`, inviteID, targetUserID).Scan(&projectID, &expires, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return SharedInvite{}, ErrNotFound
	}
	if err != nil {
		return SharedInvite{}, err
	}
	if status != "pending" {
		return SharedInvite{}, ErrConflict
	}
	if now.Unix() >= expires {
		_, _ = tx.ExecContext(ctx, `UPDATE shared_project_invites SET status='expired',acted_at=? WHERE id=? AND status='pending'`, now.Unix(), inviteID)
		if err := tx.Commit(); err != nil {
			return SharedInvite{}, err
		}
		return SharedInvite{}, ErrExpired
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO shared_project_members(project_id,user_id,role,state,joined_at) VALUES(?,?,'member','pending_acl',?)`, projectID, targetUserID, now.Unix()); err != nil {
		return SharedInvite{}, fmt.Errorf("stage shared member: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return SharedInvite{}, err
	}
	return s.SharedInviteForUser(ctx, inviteID, targetUserID)
}

func (s *Store) FinishAcceptSharedInvite(ctx context.Context, inviteID string, targetUserID int64, success bool, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var projectID string
	if err := tx.QueryRowContext(ctx, `SELECT project_id FROM shared_project_invites WHERE id=? AND target_user_id=? AND status='pending'`, inviteID, targetUserID).Scan(&projectID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if success {
		result, err := tx.ExecContext(ctx, `UPDATE shared_project_members SET state='accepted',joined_at=? WHERE project_id=? AND user_id=? AND state='pending_acl'`, now.Unix(), projectID, targetUserID)
		if err != nil {
			return err
		}
		if err := requireChanged(result); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE shared_project_invites SET status='accepted',acted_at=? WHERE id=? AND status='pending'`, now.Unix(), inviteID); err != nil {
			return err
		}
	} else {
		if _, err := tx.ExecContext(ctx, `DELETE FROM shared_project_members WHERE project_id=? AND user_id=? AND state='pending_acl'`, projectID, targetUserID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DeclineSharedInvite(ctx context.Context, inviteID string, targetUserID int64, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE shared_project_invites SET status='declined',acted_at=? WHERE id=? AND target_user_id=? AND status='pending'`, now.Unix(), inviteID, targetUserID)
	if err != nil {
		return err
	}
	return requireChanged(result)
}

func (s *Store) RevokeSharedInvite(ctx context.Context, inviteID string, ownerUserID int64, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE shared_project_invites SET status='revoked',acted_at=? WHERE id=? AND status='pending' AND EXISTS(SELECT 1 FROM shared_projects p WHERE p.id=shared_project_invites.project_id AND p.owner_user_id=?)`, now.Unix(), inviteID, ownerUserID)
	if err != nil {
		return err
	}
	return requireChanged(result)
}

func (s *Store) CreateSharedInviteLink(ctx context.Context, link SharedInviteLink, ownerUserID int64, now time.Time) (SharedInviteLink, error) {
	link.Token = strings.TrimSpace(link.Token)
	if len(link.Token) != 32 || strings.TrimSpace(link.ProjectID) == "" || !link.ExpiresAt.After(now) {
		return SharedInviteLink{}, errors.New("shared invite link fields are invalid")
	}
	project, err := s.SharedProjectForUser(ctx, link.ProjectID, ownerUserID, true)
	if err != nil || project.CurrentRole != "owner" || project.State != "active" {
		return SharedInviteLink{}, ErrForbidden
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SharedInviteLink{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE shared_project_invite_links SET status='revoked' WHERE project_id=? AND status='active'`, link.ProjectID); err != nil {
		return SharedInviteLink{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO shared_project_invite_links(token,project_id,inviter_user_id,status,created_at,expires_at) VALUES(?,?,?,'active',?,?)`, link.Token, link.ProjectID, ownerUserID, now.Unix(), link.ExpiresAt.Unix()); err != nil {
		return SharedInviteLink{}, err
	}
	if err := tx.Commit(); err != nil {
		return SharedInviteLink{}, err
	}
	link.InviterUserID = ownerUserID
	return link, nil
}

func (s *Store) BeginAcceptSharedInviteLink(ctx context.Context, token string, targetUserID int64, now time.Time) (SharedInviteLink, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SharedInviteLink{}, err
	}
	defer tx.Rollback()
	var link SharedInviteLink
	var expires int64
	err = tx.QueryRowContext(ctx, `SELECT l.project_id,l.inviter_user_id,l.expires_at FROM shared_project_invite_links l JOIN shared_projects p ON p.id=l.project_id JOIN portal_users u ON u.id=? AND u.enabled=1 AND u.is_admin=0 WHERE l.token=? AND l.status='active' AND p.state='active' AND p.owner_user_id=l.inviter_user_id`, targetUserID, strings.TrimSpace(token)).Scan(&link.ProjectID, &link.InviterUserID, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return SharedInviteLink{}, ErrNotFound
	}
	if err != nil {
		return SharedInviteLink{}, err
	}
	link.Token = strings.TrimSpace(token)
	link.ExpiresAt = time.Unix(expires, 0).UTC()
	if !link.ExpiresAt.After(now) {
		_, _ = tx.ExecContext(ctx, `UPDATE shared_project_invite_links SET status='expired' WHERE token=? AND status='active'`, link.Token)
		if err := tx.Commit(); err != nil {
			return SharedInviteLink{}, err
		}
		return SharedInviteLink{}, ErrExpired
	}
	if targetUserID == link.InviterUserID {
		return SharedInviteLink{}, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO shared_project_members(project_id,user_id,role,state,joined_at) VALUES(?,?,'member','pending_acl',?)`, link.ProjectID, targetUserID, now.Unix()); err != nil {
		return SharedInviteLink{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return SharedInviteLink{}, err
	}
	return link, nil
}

func (s *Store) FinishAcceptSharedInviteLink(ctx context.Context, projectID string, targetUserID int64, success bool, now time.Time) error {
	if success {
		result, err := s.db.ExecContext(ctx, `UPDATE shared_project_members SET state='accepted',joined_at=? WHERE project_id=? AND user_id=? AND state='pending_acl'`, now.Unix(), projectID, targetUserID)
		if err != nil {
			return err
		}
		return requireChanged(result)
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM shared_project_members WHERE project_id=? AND user_id=? AND state='pending_acl'`, projectID, targetUserID)
	if err != nil {
		return err
	}
	return requireChanged(result)
}

func (s *Store) SetSharedItemHidden(ctx context.Context, userID int64, kind, itemID string, hidden bool, now time.Time) error {
	if kind != "project" && kind != "conversation" {
		return errors.New("shared hidden item kind is invalid")
	}
	if hidden {
		_, err := s.db.ExecContext(ctx, `INSERT INTO shared_hidden_items(user_id,item_kind,item_id,hidden_at) VALUES(?,?,?,?) ON CONFLICT(user_id,item_kind,item_id) DO UPDATE SET hidden_at=excluded.hidden_at`, userID, kind, itemID, now.Unix())
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM shared_hidden_items WHERE user_id=? AND item_kind=? AND item_id=?`, userID, kind, itemID)
	return err
}

func (s *Store) CreateSharedConversation(ctx context.Context, conversation SharedConversation, creatorUserID int64, now time.Time) (SharedConversation, error) {
	conversation.ID, conversation.Name, conversation.AssistantID = strings.TrimSpace(conversation.ID), strings.TrimSpace(conversation.Name), strings.TrimSpace(conversation.AssistantID)
	conversation.ModelID, conversation.ThinkingEffort = strings.TrimSpace(conversation.ModelID), strings.TrimSpace(conversation.ThinkingEffort)
	if conversation.ThinkingEffort == "" {
		conversation.ThinkingEffort = "low"
	}
	if len(conversation.ID) != 32 || conversation.Name == "" || len(conversation.Name) > 128 || conversation.AssistantID == "" || conversation.ModelID == "" || conversation.ThinkingEffort == "" || (conversation.AssistantBackend != "codex" && conversation.AssistantBackend != "kimi") {
		return SharedConversation{}, errors.New("shared conversation fields are invalid")
	}
	project, err := s.SharedProjectForUser(ctx, conversation.ProjectID, creatorUserID, true)
	if err != nil || project.State != "active" {
		return SharedConversation{}, ErrForbidden
	}
	stamp := now.Unix()
	_, err = s.db.ExecContext(ctx, `INSERT INTO shared_conversations(id,project_id,name,assistant_id,assistant_backend,model_id,thinking_effort,runtime_owner_user_id,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,'idle',?,?)`, conversation.ID, conversation.ProjectID, conversation.Name, conversation.AssistantID, conversation.AssistantBackend, conversation.ModelID, conversation.ThinkingEffort, project.OwnerUserID, stamp, stamp)
	if err != nil {
		return SharedConversation{}, err
	}
	conversation.RuntimeOwnerUserID = project.OwnerUserID
	conversation.State = "idle"
	conversation.CreatedAt, conversation.UpdatedAt = now.UTC(), now.UTC()
	return conversation, nil
}

func (s *Store) SharedConversationForUser(ctx context.Context, conversationID string, userID int64) (SharedConversation, error) {
	var out SharedConversation
	var runtime sql.NullString
	var runtimeOwner sql.NullInt64
	var created, updated int64
	var pinned int
	var pinnedAt sql.NullInt64
	var hidden int
	err := s.db.QueryRowContext(ctx, `SELECT c.id,c.project_id,p.name,m.role,c.name,c.assistant_id,c.assistant_backend,c.model_id,c.thinking_effort,c.runtime_conversation_id,c.runtime_owner_user_id,c.state,c.last_ai_message_seq,COALESCE(us.pinned,0),us.pinned_at,EXISTS(SELECT 1 FROM shared_hidden_items h WHERE h.user_id=? AND h.item_kind='conversation' AND h.item_id=c.id),c.created_at,c.updated_at FROM shared_conversations c JOIN shared_projects p ON p.id=c.project_id JOIN shared_project_members m ON m.project_id=c.project_id AND m.user_id=? AND m.state='accepted' LEFT JOIN shared_conversation_user_state us ON us.conversation_id=c.id AND us.user_id=? WHERE c.id=?`, userID, userID, userID, strings.TrimSpace(conversationID)).Scan(&out.ID, &out.ProjectID, &out.ProjectName, &out.CurrentRole, &out.Name, &out.AssistantID, &out.AssistantBackend, &out.ModelID, &out.ThinkingEffort, &runtime, &runtimeOwner, &out.State, &out.LastAIMessageSeq, &pinned, &pinnedAt, &hidden, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return SharedConversation{}, ErrNotFound
	}
	if err != nil {
		return SharedConversation{}, err
	}
	out.RuntimeConversationID, out.RuntimeOwnerUserID = runtime.String, runtimeOwner.Int64
	out.Pinned, out.Hidden = pinned != 0, hidden != 0
	if pinnedAt.Valid {
		value := time.Unix(pinnedAt.Int64, 0).UTC()
		out.PinnedAt = &value
	}
	out.CreatedAt, out.UpdatedAt = time.Unix(created, 0).UTC(), time.Unix(updated, 0).UTC()
	return out, nil
}

func (s *Store) ListSharedConversations(ctx context.Context, userID int64) ([]SharedConversation, error) {
	return s.listSharedConversations(ctx, userID, false)
}

func (s *Store) ListAllSharedConversations(ctx context.Context, userID int64) ([]SharedConversation, error) {
	return s.listSharedConversations(ctx, userID, true)
}

func (s *Store) listSharedConversations(ctx context.Context, userID int64, includeHidden bool) ([]SharedConversation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT c.id FROM shared_conversations c JOIN shared_project_members m ON m.project_id=c.project_id AND m.user_id=? AND m.state='accepted' LEFT JOIN shared_conversation_user_state us ON us.conversation_id=c.id AND us.user_id=? WHERE (? OR NOT EXISTS(SELECT 1 FROM shared_hidden_items h WHERE h.user_id=? AND h.item_kind='conversation' AND h.item_id=c.id)) ORDER BY COALESCE(us.pinned,0) DESC,us.pinned_at DESC,c.updated_at DESC,c.id`, userID, userID, boolInt(includeHidden), userID)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	result := make([]SharedConversation, 0, len(ids))
	for _, id := range ids {
		conversation, err := s.SharedConversationForUser(ctx, id, userID)
		if err != nil {
			return nil, err
		}
		result = append(result, conversation)
	}
	return result, nil
}

func (s *Store) UpdateSharedConversationMetadata(ctx context.Context, conversationID string, userID int64, name *string, pinned *bool, hidden *bool, now time.Time) (SharedConversation, error) {
	conversationID = strings.TrimSpace(conversationID)
	operations := 0
	if name != nil {
		operations++
		value := strings.TrimSpace(*name)
		if value == "" || len(value) > 128 {
			return SharedConversation{}, errors.New("shared conversation name is invalid")
		}
		*name = value
	}
	if pinned != nil {
		operations++
	}
	if hidden != nil {
		operations++
	}
	if operations != 1 {
		return SharedConversation{}, errors.New("exactly one shared conversation metadata operation is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SharedConversation{}, err
	}
	defer tx.Rollback()
	var projectID string
	if err := tx.QueryRowContext(ctx, `SELECT c.project_id FROM shared_conversations c JOIN shared_project_members m ON m.project_id=c.project_id AND m.user_id=? AND m.state='accepted' WHERE c.id=?`, userID, conversationID).Scan(&projectID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SharedConversation{}, ErrNotFound
		}
		return SharedConversation{}, err
	}
	if name != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE shared_conversations SET name=?,updated_at=? WHERE id=?`, *name, now.Unix(), conversationID); err != nil {
			return SharedConversation{}, err
		}
	}
	if pinned != nil {
		pinnedAt := any(nil)
		if *pinned {
			pinnedAt = now.Unix()
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO shared_conversation_user_state(user_id,conversation_id,pinned,pinned_at) VALUES(?,?,?,?) ON CONFLICT(user_id,conversation_id) DO UPDATE SET pinned=excluded.pinned,pinned_at=excluded.pinned_at`, userID, conversationID, boolInt(*pinned), pinnedAt); err != nil {
			return SharedConversation{}, err
		}
	}
	if hidden != nil {
		if *hidden {
			if _, err := tx.ExecContext(ctx, `INSERT INTO shared_hidden_items(user_id,item_kind,item_id,hidden_at) VALUES(?,'conversation',?,?) ON CONFLICT(user_id,item_kind,item_id) DO UPDATE SET hidden_at=excluded.hidden_at`, userID, conversationID, now.Unix()); err != nil {
				return SharedConversation{}, err
			}
		} else if _, err := tx.ExecContext(ctx, `DELETE FROM shared_hidden_items WHERE user_id=? AND item_kind='conversation' AND item_id=?`, userID, conversationID); err != nil {
			return SharedConversation{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return SharedConversation{}, err
	}
	return s.SharedConversationForUser(ctx, conversationID, userID)
}

func (s *Store) UpdateSharedConversationRuntime(ctx context.Context, conversationID string, userID int64, modelID, thinkingEffort string, now time.Time) (SharedConversation, error) {
	modelID, thinkingEffort = strings.TrimSpace(modelID), strings.TrimSpace(thinkingEffort)
	if modelID == "" || len(modelID) > 256 || thinkingEffort == "" || len(thinkingEffort) > 32 {
		return SharedConversation{}, errors.New("shared conversation runtime configuration is invalid")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE shared_conversations SET model_id=?,thinking_effort=?,runtime_conversation_id=NULL,updated_at=? WHERE id=? AND state='idle' AND EXISTS(SELECT 1 FROM shared_project_members m WHERE m.project_id=shared_conversations.project_id AND m.user_id=? AND m.state='accepted')`, modelID, thinkingEffort, now.Unix(), strings.TrimSpace(conversationID), userID)
	if err != nil {
		return SharedConversation{}, err
	}
	if err := requireChanged(result); err != nil {
		return SharedConversation{}, ErrConflict
	}
	return s.SharedConversationForUser(ctx, conversationID, userID)
}

func (s *Store) StopSharedAIRun(ctx context.Context, conversationID string, userID int64, now time.Time) (SharedAIRun, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SharedAIRun{}, err
	}
	defer tx.Rollback()
	var run SharedAIRun
	err = tx.QueryRowContext(ctx, `SELECT r.id,r.conversation_id,r.trigger_message_id,r.provider,r.owner_user_id,r.context_from_seq,r.context_through_seq FROM shared_ai_runs r JOIN shared_conversations c ON c.id=r.conversation_id JOIN shared_project_members m ON m.project_id=c.project_id AND m.user_id=? AND m.state='accepted' WHERE r.conversation_id=? AND r.state='running'`, userID, strings.TrimSpace(conversationID)).Scan(&run.ID, &run.ConversationID, &run.TriggerMessageID, &run.Provider, &run.OwnerUserID, &run.ContextFromSeq, &run.ContextThroughSeq)
	if errors.Is(err, sql.ErrNoRows) {
		return SharedAIRun{}, ErrNotFound
	}
	if err != nil {
		return SharedAIRun{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE shared_ai_runs SET state='stopped',finished_at=? WHERE id=? AND state='running'`, now.Unix(), run.ID); err != nil {
		return SharedAIRun{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE shared_conversations SET state='idle',updated_at=? WHERE id=? AND state='running'`, now.Unix(), run.ConversationID); err != nil {
		return SharedAIRun{}, err
	}
	id, err := NewStableID()
	if err != nil {
		return SharedAIRun{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO shared_messages(id,conversation_id,kind,body,created_at) VALUES(?,?,'system',?,?)`, id, run.ConversationID, "AI run was stopped. Messages sent during the run remain in the next shared context.", now.Unix()); err != nil {
		return SharedAIRun{}, err
	}
	if err := tx.Commit(); err != nil {
		return SharedAIRun{}, err
	}
	return run, nil
}

func (s *Store) AddSharedMessage(ctx context.Context, message SharedMessage, now time.Time) (SharedMessage, error) {
	message.ID, message.Conversation, message.Body = strings.TrimSpace(message.ID), strings.TrimSpace(message.Conversation), strings.TrimSpace(message.Body)
	if len(message.ID) != 32 || message.Conversation == "" || message.Body == "" || len(message.Body) > 128*1024 || message.AuthorUserID == nil || message.Kind != "user" {
		return SharedMessage{}, errors.New("shared user message is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SharedMessage{}, err
	}
	defer tx.Rollback()
	var assistantID, projectID string
	err = tx.QueryRowContext(ctx, `SELECT c.assistant_id,c.project_id,COALESCE(NULLIF(author.display_name,''),author.username) FROM shared_conversations c JOIN shared_project_members m ON m.project_id=c.project_id AND m.user_id=? AND m.state='accepted' JOIN portal_users author ON author.id=m.user_id AND author.enabled=1 JOIN shared_projects p ON p.id=c.project_id AND p.state='active' WHERE c.id=?`, *message.AuthorUserID, message.Conversation).Scan(&assistantID, &projectID, &message.AuthorName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SharedMessage{}, ErrForbidden
		}
		return SharedMessage{}, err
	}
	seenMentions := make(map[string]bool, len(message.Mentions))
	for _, mention := range message.Mentions {
		mention.ID = strings.TrimSpace(mention.ID)
		key := mention.Kind + "\x00" + mention.ID
		if (mention.Kind != "assistant" && mention.Kind != "member" && mention.Kind != "file") || mention.ID == "" || seenMentions[key] {
			return SharedMessage{}, errors.New("shared message mention is invalid")
		}
		seenMentions[key] = true
		if mention.Kind == "assistant" && mention.ID != assistantID {
			return SharedMessage{}, errors.New("shared message may only mention its fixed assistant")
		}
		if mention.Kind == "member" {
			memberID, parseErr := strconv.ParseInt(mention.ID, 10, 64)
			var accepted int
			if parseErr != nil || memberID <= 0 || tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM shared_project_members WHERE project_id=? AND user_id=? AND state='accepted'`, projectID, memberID).Scan(&accepted) != nil || accepted != 1 {
				return SharedMessage{}, errors.New("shared message member mention is not an accepted project member")
			}
		}
		if mention.Kind == "file" && !validStableSharedFileID(projectID, mention.ID) {
			return SharedMessage{}, errors.New("shared message file mention is outside the shared project")
		}
	}
	for _, attachment := range message.Attachments {
		if !validStableSharedFileID(projectID, attachment) {
			return SharedMessage{}, errors.New("shared message attachment is outside the shared project")
		}
	}
	mentions, err := json.Marshal(message.Mentions)
	if err != nil {
		return SharedMessage{}, err
	}
	attachments, err := json.Marshal(message.Attachments)
	if err != nil {
		return SharedMessage{}, err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO shared_messages(id,conversation_id,author_user_id,kind,body,mentions_json,attachments_json,created_at) VALUES(?,?,?,'user',?,?,?,?)`, message.ID, message.Conversation, *message.AuthorUserID, message.Body, string(mentions), string(attachments), now.Unix())
	if err != nil {
		return SharedMessage{}, err
	}
	message.Seq, err = result.LastInsertId()
	if err != nil {
		return SharedMessage{}, err
	}
	if err := tx.Commit(); err != nil {
		return SharedMessage{}, err
	}
	message.CreatedAt = now.UTC()
	return message, nil
}

func validStableSharedFileID(projectID, value string) bool {
	value = strings.TrimSpace(strings.ReplaceAll(value, `\`, "/"))
	prefix := "shared://" + projectID + "/"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	relative := strings.TrimPrefix(value, prefix)
	clean := path.Clean(relative)
	if relative == "" || clean == "." || clean == ".." || clean != relative || strings.HasPrefix(clean, "../") || strings.Contains(clean, ":") || strings.IndexFunc(clean, unicode.IsControl) >= 0 {
		return false
	}
	for _, segment := range strings.Split(clean, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func (s *Store) ReserveSharedAIRun(ctx context.Context, runID string, message SharedMessage, provider string, payers []SharedAIRunPayer, now time.Time) (SharedAIRun, error) {
	if len(runID) != 32 || message.Seq <= 0 || message.ID == "" || (provider != "codex" && provider != "kimi") || len(payers) == 0 {
		return SharedAIRun{}, errors.New("shared AI reservation is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SharedAIRun{}, err
	}
	defer tx.Rollback()
	var state string
	var lastAI, ownerUserID int64
	if err := tx.QueryRowContext(ctx, `SELECT state,last_ai_message_seq,runtime_owner_user_id FROM shared_conversations WHERE id=?`, message.Conversation).Scan(&state, &lastAI, &ownerUserID); err != nil {
		return SharedAIRun{}, err
	}
	if state != "idle" || ownerUserID <= 0 || message.Seq <= lastAI {
		return SharedAIRun{}, ErrConflict
	}
	contextFrom := lastAI + 1
	if lastAI == 0 {
		contextFrom = 0
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO shared_ai_runs(id,conversation_id,trigger_message_id,provider,state,owner_user_id,context_from_seq,context_through_seq,created_at) VALUES(?,?,?,?,'reserved',?,?,?,?)`, runID, message.Conversation, message.ID, provider, ownerUserID, contextFrom, message.Seq, now.Unix()); err != nil {
		return SharedAIRun{}, err
	}
	denominator := len(payers)
	seen := make(map[int64]bool, denominator)
	for _, payer := range payers {
		payer.KeyID = strings.TrimSpace(payer.KeyID)
		if payer.UserID <= 0 || payer.KeyID == "" || seen[payer.UserID] {
			return SharedAIRun{}, errors.New("shared AI payer set is invalid")
		}
		seen[payer.UserID] = true
		if _, err := tx.ExecContext(ctx, `INSERT INTO shared_ai_run_payers(run_id,user_id,key_id,share_denominator) SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM shared_project_members m JOIN shared_conversations c ON c.project_id=m.project_id WHERE c.id=? AND m.user_id=? AND m.state='accepted')`, runID, payer.UserID, payer.KeyID, denominator, message.Conversation, payer.UserID); err != nil {
			return SharedAIRun{}, err
		}
	}
	var inserted int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM shared_ai_run_payers WHERE run_id=?`, runID).Scan(&inserted); err != nil || inserted != denominator {
		return SharedAIRun{}, errors.New("shared AI payer membership changed during reservation")
	}
	result, err := tx.ExecContext(ctx, `UPDATE shared_conversations SET state='running',updated_at=? WHERE id=? AND state='idle'`, now.Unix(), message.Conversation)
	if err != nil {
		return SharedAIRun{}, err
	}
	if err := requireChanged(result); err != nil {
		return SharedAIRun{}, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `UPDATE shared_ai_runs SET state='running' WHERE id=? AND state='reserved'`, runID); err != nil {
		return SharedAIRun{}, err
	}
	if err := tx.Commit(); err != nil {
		return SharedAIRun{}, err
	}
	return SharedAIRun{ID: runID, ConversationID: message.Conversation, TriggerMessageID: message.ID, Provider: provider, OwnerUserID: ownerUserID, ContextFromSeq: contextFrom, ContextThroughSeq: message.Seq}, nil
}

func (s *Store) SharedUserMessagesRange(ctx context.Context, conversationID string, fromSeq, throughSeq int64) ([]SharedMessage, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT m.seq,m.id,m.conversation_id,m.author_user_id,COALESCE(NULLIF(u.display_name,''),u.username,''),m.kind,m.body,m.mentions_json,m.attachments_json,m.created_at FROM shared_messages m LEFT JOIN portal_users u ON u.id=m.author_user_id WHERE m.conversation_id=? AND m.seq>=? AND m.seq<=? AND m.kind='user' ORDER BY m.seq`, conversationID, fromSeq, throughSeq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSharedMessages(rows)
}

func scanSharedMessages(rows *sql.Rows) ([]SharedMessage, error) {
	var result []SharedMessage
	for rows.Next() {
		var item SharedMessage
		var author sql.NullInt64
		var mentions, attachments string
		var created int64
		if err := rows.Scan(&item.Seq, &item.ID, &item.Conversation, &author, &item.AuthorName, &item.Kind, &item.Body, &mentions, &attachments, &created); err != nil {
			return nil, err
		}
		if author.Valid {
			value := author.Int64
			item.AuthorUserID = &value
		}
		if err := json.Unmarshal([]byte(mentions), &item.Mentions); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(attachments), &item.Attachments); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(created, 0).UTC()
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) FinishSharedAIRun(ctx context.Context, run SharedAIRun, runtimeConversationID, assistantBody string, recovered bool, runErr error, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	state := "succeeded"
	if runErr != nil {
		state = "failed"
	}
	result, err := tx.ExecContext(ctx, `UPDATE shared_ai_runs SET state=?,finished_at=? WHERE id=? AND state='running'`, state, now.Unix(), run.ID)
	if err != nil {
		return err
	}
	if err := requireChanged(result); err != nil {
		var existingState string
		if stateErr := tx.QueryRowContext(ctx, `SELECT state FROM shared_ai_runs WHERE id=?`, run.ID).Scan(&existingState); stateErr == nil && existingState == "stopped" {
			return nil
		}
		return err
	}
	if recovered {
		id, err := NewStableID()
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO shared_messages(id,conversation_id,kind,body,created_at) VALUES(?,?,'system',?,?)`, id, run.ConversationID, "AI session was missing and was rebuilt from the complete shared history.", now.Unix()); err != nil {
			return err
		}
	}
	if runErr == nil {
		id, err := NewStableID()
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO shared_messages(id,conversation_id,kind,body,created_at) VALUES(?,?,'assistant',?,?)`, id, run.ConversationID, assistantBody, now.Unix()); err != nil {
			return err
		}
	} else {
		id, err := NewStableID()
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO shared_messages(id,conversation_id,kind,body,created_at) VALUES(?,?,'system',?,?)`, id, run.ConversationID, "AI run failed; the triggering messages remain available for retry.", now.Unix()); err != nil {
			return err
		}
	}
	lastAI := int64(0)
	if runErr == nil {
		lastAI = run.ContextThroughSeq
	}
	if _, err := tx.ExecContext(ctx, `UPDATE shared_conversations SET runtime_conversation_id=CASE WHEN ?<>'' THEN ? ELSE runtime_conversation_id END,state='idle',last_ai_message_seq=CASE WHEN ?>0 THEN ? ELSE last_ai_message_seq END,updated_at=? WHERE id=? AND state='running'`, runtimeConversationID, runtimeConversationID, lastAI, lastAI, now.Unix(), run.ConversationID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AddSharedSystemMessage(ctx context.Context, conversationID, body string, now time.Time) error {
	id, err := NewStableID()
	if err != nil {
		return err
	}
	body = strings.TrimSpace(body)
	if body == "" || len(body) > 16*1024 {
		return errors.New("shared system message is invalid")
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO shared_messages(id,conversation_id,kind,body,created_at) SELECT ?,?,'system',?,? WHERE EXISTS(SELECT 1 FROM shared_conversations WHERE id=?)`, id, conversationID, body, now.Unix(), conversationID)
	return err
}

func (s *Store) ListSharedMessages(ctx context.Context, conversationID string, userID int64, afterSeq int64, limit int) ([]SharedMessage, error) {
	if _, err := s.SharedConversationForUser(ctx, conversationID, userID); err != nil {
		return nil, err
	}
	if afterSeq < 0 {
		return nil, errors.New("shared message cursor is invalid")
	}
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT m.seq,m.id,m.conversation_id,m.author_user_id,COALESCE(u.display_name,''),m.kind,m.body,m.mentions_json,m.attachments_json,m.created_at FROM shared_messages m LEFT JOIN portal_users u ON u.id=m.author_user_id WHERE m.conversation_id=? AND m.seq>? ORDER BY m.seq LIMIT ?`, conversationID, afterSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []SharedMessage
	for rows.Next() {
		var item SharedMessage
		var author sql.NullInt64
		var mentions, attachments string
		var created int64
		if err := rows.Scan(&item.Seq, &item.ID, &item.Conversation, &author, &item.AuthorName, &item.Kind, &item.Body, &mentions, &attachments, &created); err != nil {
			return nil, err
		}
		if author.Valid {
			value := author.Int64
			item.AuthorUserID = &value
		}
		if err := json.Unmarshal([]byte(mentions), &item.Mentions); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(attachments), &item.Attachments); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(created, 0).UTC()
		result = append(result, item)
	}
	return result, rows.Err()
}

// ListSharedMessagesForUserAfter replays the global shared-message sequence for
// an authenticated member. It backs SSE Last-Event-ID recovery without
// exposing conversations from projects the user cannot currently access.
func (s *Store) ListSharedMessagesForUserAfter(ctx context.Context, userID, afterSeq int64, limit int) ([]SharedMessage, error) {
	if userID <= 0 || afterSeq < 0 {
		return nil, errors.New("shared event cursor is invalid")
	}
	if limit < 1 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT m.seq,m.id,m.conversation_id,m.author_user_id,COALESCE(u.display_name,''),m.kind,m.body,m.mentions_json,m.attachments_json,m.created_at FROM shared_messages m JOIN shared_conversations c ON c.id=m.conversation_id JOIN shared_project_members member ON member.project_id=c.project_id AND member.user_id=? AND member.state='accepted' LEFT JOIN portal_users u ON u.id=m.author_user_id WHERE m.seq>? ORDER BY m.seq LIMIT ?`, userID, afterSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSharedMessages(rows)
}
