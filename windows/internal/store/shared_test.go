package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestSharedProjectUsesStableIDsMembershipAndStructuredMentions(t *testing.T) {
	ctx := context.Background()
	data := openTestStore(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	owner, err := data.CreateUser(ctx, "owner", "hash", "S-1-5-21-1-2001", `SERVER\owner`, false, now)
	if err != nil {
		t.Fatal(err)
	}
	projectID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	project, err := data.CreateSharedProject(ctx, SharedProject{ID: projectID, OwnerUserID: owner.ID, Name: "共享研发", SourceKind: "new"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if project.State != "provisioning" || project.CurrentRole != "owner" || project.OwnerSID != owner.WindowsSID || project.MemberCount != 1 {
		t.Fatalf("unexpected project: %+v", project)
	}
	if err := data.SetSharedProjectProvisioningResult(ctx, projectID, true, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	conversation, err := data.CreateSharedConversation(ctx, SharedConversation{ID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ProjectID: projectID, Name: "实现", AssistantID: "codex", AssistantBackend: "codex", ModelID: "gpt-5.6-sol"}, owner.ID, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	messageID := "cccccccccccccccccccccccccccccccc"
	message, err := data.AddSharedMessage(ctx, SharedMessage{ID: messageID, Conversation: conversation.ID, AuthorUserID: &owner.ID, Kind: "user", Body: "请检查", Mentions: []SharedMention{{Kind: "assistant", ID: "codex"}}}, now.Add(3*time.Second))
	if err != nil || message.Seq != 1 || message.AuthorName != "owner" {
		t.Fatalf("message=%+v err=%v", message, err)
	}
	if _, err := data.AddSharedMessage(ctx, SharedMessage{ID: "dddddddddddddddddddddddddddddddd", Conversation: conversation.ID, AuthorUserID: &owner.ID, Kind: "user", Body: "bad", Mentions: []SharedMention{{Kind: "plain-text", ID: "@Codex"}}}, now); err == nil {
		t.Fatal("unstructured mention was accepted")
	}
	if _, err := data.AddSharedMessage(ctx, SharedMessage{ID: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", Conversation: conversation.ID, AuthorUserID: &owner.ID, Kind: "user", Body: "spoof", Mentions: []SharedMention{{Kind: "member", ID: "9999"}}}, now); err == nil {
		t.Fatal("non-member mention was accepted")
	}
	if _, err := data.AddSharedMessage(ctx, SharedMessage{ID: "ffffffffffffffffffffffffffffffff", Conversation: conversation.ID, AuthorUserID: &owner.ID, Kind: "user", Body: "escape", Attachments: []string{"shared://" + projectID + "/../secret"}}, now); err == nil {
		t.Fatal("cross-project attachment path was accepted")
	}
}

func TestSharedProjectHiddenStateIsPerUserAndDoesNotDeleteProject(t *testing.T) {
	ctx := context.Background()
	data := openTestStore(t)
	now := time.Unix(1_800_000_100, 0).UTC()
	owner, _ := data.CreateUser(ctx, "owner2", "hash", "S-1-5-21-1-2002", `SERVER\owner2`, false, now)
	id := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	if _, err := data.CreateSharedProject(ctx, SharedProject{ID: id, OwnerUserID: owner.ID, Name: "不可删除", SourceKind: "new"}, now); err != nil {
		t.Fatal(err)
	}
	if err := data.SetSharedItemHidden(ctx, owner.ID, "project", id, true, now); err != nil {
		t.Fatal(err)
	}
	if _, err := data.SharedProjectForUser(ctx, id, owner.ID, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("hidden project remained visible: %v", err)
	}
	if project, err := data.SharedProjectForUser(ctx, id, owner.ID, true); err != nil || !project.Hidden {
		t.Fatalf("hidden project could not be restored: project=%+v err=%v", project, err)
	}
}

func TestListSharedProjectsReleasesSingleConnectionBeforeLoadingDetails(t *testing.T) {
	data := openTestStore(t)
	now := time.Unix(1_800_000_110, 0).UTC()
	owner, err := data.CreateUser(context.Background(), "list-owner", "hash", "S-1-5-21-1-2010", `SERVER\list-owner`, false, now)
	if err != nil {
		t.Fatal(err)
	}
	for index, id := range []string{"11111111111111111111111111111111", "22222222222222222222222222222222"} {
		if _, err := data.CreateSharedProject(context.Background(), SharedProject{ID: id, OwnerUserID: owner.ID, Name: "project", SourceKind: "new"}, now.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	projects, err := data.ListSharedProjects(ctx, owner.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != 2 {
		t.Fatalf("projects=%+v", projects)
	}
}

func TestSharedConversationMetadataUsesPersonalPinAndHideState(t *testing.T) {
	ctx := context.Background()
	data := openTestStore(t)
	now := time.Unix(1_800_000_125, 0).UTC()
	owner, _ := data.CreateUser(ctx, "conversation-owner", "hash", "S-1-5-21-1-2025", `SERVER\conversation-owner`, false, now)
	projectID := "abababababababababababababababab"
	conversationID := "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	if _, err := data.CreateSharedProject(ctx, SharedProject{ID: projectID, OwnerUserID: owner.ID, Name: "共享项目", SourceKind: "new"}, now); err != nil {
		t.Fatal(err)
	}
	if err := data.SetSharedProjectProvisioningResult(ctx, projectID, true, now); err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateSharedConversation(ctx, SharedConversation{ID: conversationID, ProjectID: projectID, Name: "原名", AssistantID: "codex", AssistantBackend: "codex", ModelID: "gpt"}, owner.ID, now); err != nil {
		t.Fatal(err)
	}
	pinned := true
	conversation, err := data.UpdateSharedConversationMetadata(ctx, conversationID, owner.ID, nil, &pinned, nil, now.Add(time.Second))
	if err != nil || !conversation.Pinned || conversation.PinnedAt == nil {
		t.Fatalf("pin result=%+v err=%v", conversation, err)
	}
	hidden := true
	conversation, err = data.UpdateSharedConversationMetadata(ctx, conversationID, owner.ID, nil, nil, &hidden, now.Add(2*time.Second))
	if err != nil || !conversation.Hidden {
		t.Fatalf("hide result=%+v err=%v", conversation, err)
	}
	if visible, err := data.ListSharedConversations(ctx, owner.ID); err != nil || len(visible) != 0 {
		t.Fatalf("hidden conversation remained visible: %+v err=%v", visible, err)
	}
	if all, err := data.ListAllSharedConversations(ctx, owner.ID); err != nil || len(all) != 1 || !all[0].Hidden || !all[0].Pinned {
		t.Fatalf("hidden conversation restore list=%+v err=%v", all, err)
	}
	name := "新名称"
	conversation, err = data.UpdateSharedConversationMetadata(ctx, conversationID, owner.ID, &name, nil, nil, now.Add(3*time.Second))
	if err != nil || conversation.Name != name {
		t.Fatalf("rename result=%+v err=%v", conversation, err)
	}
}

func TestSharedEventReplayOnlyReturnsCurrentlyAuthorizedProjects(t *testing.T) {
	ctx := context.Background()
	data := openTestStore(t)
	now := time.Unix(1_800_000_150, 0).UTC()
	owner, _ := data.CreateUser(ctx, "event-owner", "hash", "S-1-5-21-1-2051", `SERVER\event-owner`, false, now)
	outsider, _ := data.CreateUser(ctx, "event-outsider", "hash", "S-1-5-21-1-2052", `SERVER\event-outsider`, false, now)
	projectID := "PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP"
	_, _ = data.CreateSharedProject(ctx, SharedProject{ID: projectID, OwnerUserID: owner.ID, Name: "events", SourceKind: "new"}, now)
	_ = data.SetSharedProjectProvisioningResult(ctx, projectID, true, now)
	conversationID := "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
	_, _ = data.CreateSharedConversation(ctx, SharedConversation{ID: conversationID, ProjectID: projectID, Name: "events", AssistantID: "codex", AssistantBackend: "codex", ModelID: "gpt"}, owner.ID, now)
	message, err := data.AddSharedMessage(ctx, SharedMessage{ID: "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR", Conversation: conversationID, AuthorUserID: &owner.ID, Kind: "user", Body: "private shared event"}, now)
	if err != nil {
		t.Fatal(err)
	}
	ownerReplay, err := data.ListSharedMessagesForUserAfter(ctx, owner.ID, 0, 10)
	if err != nil || len(ownerReplay) != 1 || ownerReplay[0].ID != message.ID {
		t.Fatalf("owner replay=%+v err=%v", ownerReplay, err)
	}
	outsiderReplay, err := data.ListSharedMessagesForUserAfter(ctx, outsider.ID, 0, 10)
	if err != nil || len(outsiderReplay) != 0 {
		t.Fatalf("unauthorized replay leaked messages=%+v err=%v", outsiderReplay, err)
	}
	afterReplay, err := data.ListSharedMessagesForUserAfter(ctx, owner.ID, message.Seq, 10)
	if err != nil || len(afterReplay) != 0 {
		t.Fatalf("Last-Event-ID cursor replay=%+v err=%v", afterReplay, err)
	}
}

func TestSharedInviteDoesNotAuthorizeUntilACLCommit(t *testing.T) {
	ctx := context.Background()
	data := openTestStore(t)
	now := time.Unix(1_800_000_200, 0).UTC()
	owner, _ := data.CreateUser(ctx, "invite-owner", "hash", "S-1-5-21-1-2101", `SERVER\invite-owner`, false, now)
	target, _ := data.CreateUser(ctx, "invite-target", "hash", "S-1-5-21-1-2102", `SERVER\invite-target`, false, now)
	if _, err := data.UpdateProfile(ctx, target.ID, "受邀人", true, now); err != nil {
		t.Fatal(err)
	}
	projectID := "ffffffffffffffffffffffffffffffff"
	if _, err := data.CreateSharedProject(ctx, SharedProject{ID: projectID, OwnerUserID: owner.ID, Name: "邀请项目", SourceKind: "new"}, now); err != nil {
		t.Fatal(err)
	}
	if err := data.SetSharedProjectProvisioningResult(ctx, projectID, true, now); err != nil {
		t.Fatal(err)
	}
	inviteID := "gggggggggggggggggggggggggggggggg"
	invite, err := data.CreateSharedInvite(ctx, SharedInvite{ID: inviteID, ProjectID: projectID, TargetUserID: target.ID, ExpiresAt: now.Add(time.Hour)}, owner.ID, now)
	if err != nil || invite.Status != "pending" {
		t.Fatalf("invite=%+v err=%v", invite, err)
	}
	if _, err := data.CreateSharedInvite(ctx, SharedInvite{ID: "pppppppppppppppppppppppppppppppp", ProjectID: projectID, TargetUserID: target.ID, ExpiresAt: now.Add(time.Hour)}, owner.ID, now); !errors.Is(err, ErrInviteAlreadyPending) {
		t.Fatalf("duplicate invite error=%v", err)
	}
	if _, err := data.BeginAcceptSharedInvite(ctx, inviteID, target.ID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := data.SharedProjectForUser(ctx, projectID, target.ID, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pending ACL member gained database access: %v", err)
	}
	sids, err := data.SharedProjectACLSIDs(ctx, projectID, owner.ID)
	if err != nil || len(sids) != 1 || sids[0] != target.WindowsSID {
		t.Fatalf("pending ACL SID set=%v err=%v", sids, err)
	}
	if err := data.FinishAcceptSharedInvite(ctx, inviteID, target.ID, true, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if project, err := data.SharedProjectForUser(ctx, projectID, target.ID, true); err != nil || project.CurrentRole != "member" {
		t.Fatalf("accepted member project=%+v err=%v", project, err)
	}
}

func TestSharedUserSearchIncludesEmployeesByUsernameAndDisplayName(t *testing.T) {
	ctx := context.Background()
	data := openTestStore(t)
	now := time.Unix(1_800_000_250, 0).UTC()
	requester, _ := data.CreateUser(ctx, "search-owner", "hash", "S-1-5-21-1-2151", `SERVER\search-owner`, false, now)
	target, _ := data.CreateUser(ctx, "zhangsan", "hash", "S-1-5-21-1-2152", `SERVER\zhangsan`, false, now)
	if _, err := data.UpdateProfile(ctx, target.ID, "张三", false, now); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"zhang", "张"} {
		users, err := data.SearchSharedUsers(ctx, requester.ID, query, 20)
		if err != nil || len(users) != 1 || users[0].ID != target.ID {
			t.Fatalf("query=%q users=%+v err=%v", query, users, err)
		}
	}
}

func TestSharedInviteLinkStagesEachMemberUntilACLCommit(t *testing.T) {
	ctx := context.Background()
	data := openTestStore(t)
	now := time.Unix(1_800_000_275, 0).UTC()
	owner, _ := data.CreateUser(ctx, "link-owner", "hash", "S-1-5-21-1-2171", `SERVER\link-owner`, false, now)
	target, _ := data.CreateUser(ctx, "link-target", "hash", "S-1-5-21-1-2172", `SERVER\link-target`, false, now)
	projectID := "12121212121212121212121212121212"
	_, _ = data.CreateSharedProject(ctx, SharedProject{ID: projectID, OwnerUserID: owner.ID, Name: "Link", SourceKind: "new"}, now)
	_ = data.SetSharedProjectProvisioningResult(ctx, projectID, true, now)
	link, err := data.CreateSharedInviteLink(ctx, SharedInviteLink{Token: "34343434343434343434343434343434", ProjectID: projectID, ExpiresAt: now.Add(7 * 24 * time.Hour)}, owner.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.BeginAcceptSharedInviteLink(ctx, link.Token, target.ID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := data.SharedProjectForUser(ctx, projectID, target.ID, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pending link member gained access: %v", err)
	}
	if err := data.FinishAcceptSharedInviteLink(ctx, projectID, target.ID, true, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if project, err := data.SharedProjectForUser(ctx, projectID, target.ID, true); err != nil || project.CurrentRole != "member" {
		t.Fatalf("accepted link member project=%+v err=%v", project, err)
	}
}

func TestMigrationAuditsAndDropsLegacyCollaborationTables(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "portal.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE TABLE collaboration_resources(id TEXT)`,
		`CREATE TABLE collaboration_members(id TEXT)`,
		`CREATE TABLE collaboration_invites(id TEXT)`,
		`CREATE TABLE collaboration_messages(id TEXT)`,
		`CREATE TABLE collaboration_sessions(id TEXT)`,
		`CREATE TABLE collaboration_session_payers(id TEXT)`,
		`INSERT INTO collaboration_resources(id) VALUES('legacy')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	data, err := Open(path, filepath.Join(root, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	var remaining int
	if err := data.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'collaboration_%'`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("legacy tables remaining=%d err=%v", remaining, err)
	}
	var audited int
	if err := data.db.QueryRow(`SELECT row_count FROM portal_migration_audit WHERE migration='collaboration-redesign-v6' AND item='collaboration_resources'`).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("legacy migration audit count=%d err=%v", audited, err)
	}
}

func TestSharedConversationModelSwitchIsIdleOnlyAndStopKeepsPendingContext(t *testing.T) {
	ctx := context.Background()
	data := openTestStore(t)
	now := time.Unix(1_800_000_300, 0).UTC()
	owner, _ := data.CreateUser(ctx, "run-owner", "hash", "S-1-5-21-1-2201", `SERVER\run-owner`, false, now)
	projectID := "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh"
	_, _ = data.CreateSharedProject(ctx, SharedProject{ID: projectID, OwnerUserID: owner.ID, Name: "run", SourceKind: "new"}, now)
	_ = data.SetSharedProjectProvisioningResult(ctx, projectID, true, now)
	conversationID := "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"
	conversation, err := data.CreateSharedConversation(ctx, SharedConversation{ID: conversationID, ProjectID: projectID, Name: "run", AssistantID: "codex", AssistantBackend: "codex", ModelID: "old"}, owner.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if conversation, err = data.UpdateSharedConversationRuntime(ctx, conversationID, owner.ID, "new", "high", now); err != nil || conversation.ModelID != "new" || conversation.ThinkingEffort != "high" {
		t.Fatalf("model switch=%+v err=%v", conversation, err)
	}
	message, err := data.AddSharedMessage(ctx, SharedMessage{ID: "jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj", Conversation: conversationID, AuthorUserID: &owner.ID, Kind: "user", Body: "go", Mentions: []SharedMention{{Kind: "assistant", ID: "codex"}}}, now)
	if err != nil {
		t.Fatal(err)
	}
	run, err := data.ReserveSharedAIRun(ctx, "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk", message, "codex", []SharedAIRunPayer{{UserID: owner.ID, KeyID: "key"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.UpdateSharedConversationRuntime(ctx, conversationID, owner.ID, "forbidden", "low", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("running model switch err=%v", err)
	}
	late, err := data.AddSharedMessage(ctx, SharedMessage{ID: "llllllllllllllllllllllllllllllll", Conversation: conversationID, AuthorUserID: &owner.ID, Kind: "user", Body: "next"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.StopSharedAIRun(ctx, conversationID, owner.ID, now); err != nil {
		t.Fatal(err)
	}
	if err := data.FinishSharedAIRun(ctx, run, "runtime", "late result", false, nil, now); err != nil {
		t.Fatalf("late finish after stop=%v", err)
	}
	conversation, err = data.SharedConversationForUser(ctx, conversationID, owner.ID)
	if err != nil || conversation.State != "idle" || conversation.LastAIMessageSeq != 0 {
		t.Fatalf("stopped conversation=%+v err=%v", conversation, err)
	}
	messages, err := data.SharedUserMessagesRange(ctx, conversationID, late.Seq, late.Seq)
	if err != nil || len(messages) != 1 || messages[0].Body != "next" {
		t.Fatalf("pending context=%+v err=%v", messages, err)
	}
}

func TestSharedOwnershipTransferMovesOwnerAndRuntimeAtomically(t *testing.T) {
	ctx := context.Background()
	data := openTestStore(t)
	now := time.Unix(1_800_000_400, 0).UTC()
	owner, _ := data.CreateUser(ctx, "transfer-owner", "hash", "S-1-5-21-1-2301", `SERVER\transfer-owner`, false, now)
	target, _ := data.CreateUser(ctx, "transfer-target", "hash", "S-1-5-21-1-2302", `SERVER\transfer-target`, false, now)
	_, _ = data.UpdateProfile(ctx, target.ID, "Target", true, now)
	projectID := "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm"
	_, _ = data.CreateSharedProject(ctx, SharedProject{ID: projectID, OwnerUserID: owner.ID, Name: "transfer", SourceKind: "new"}, now)
	_ = data.SetSharedProjectProvisioningResult(ctx, projectID, true, now)
	inviteID := "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn"
	_, err := data.CreateSharedInvite(ctx, SharedInvite{ID: inviteID, ProjectID: projectID, TargetUserID: target.ID, ExpiresAt: now.Add(time.Hour)}, owner.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = data.BeginAcceptSharedInvite(ctx, inviteID, target.ID, now)
	if err := data.FinishAcceptSharedInvite(ctx, inviteID, target.ID, true, now); err != nil {
		t.Fatal(err)
	}
	conversationID := "oooooooooooooooooooooooooooooooo"
	if _, err := data.CreateSharedConversation(ctx, SharedConversation{ID: conversationID, ProjectID: projectID, Name: "group", AssistantID: "codex", AssistantBackend: "codex", ModelID: "gpt", RuntimeConversationID: "old-runtime"}, owner.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := data.db.ExecContext(ctx, `UPDATE shared_conversations SET runtime_conversation_id='old-runtime' WHERE id=?`, conversationID); err != nil {
		t.Fatal(err)
	}
	if _, err := data.BeginSharedOwnershipTransfer(ctx, projectID, target.ID, owner.ID, now); err != nil {
		t.Fatal(err)
	}
	if err := data.FinishSharedOwnershipTransfer(ctx, projectID, owner.ID, target.ID, true, now); err != nil {
		t.Fatal(err)
	}
	project, err := data.SharedProjectForUser(ctx, projectID, target.ID, true)
	if err != nil || project.OwnerUserID != target.ID || project.CurrentRole != "owner" || project.State != "active" {
		t.Fatalf("transferred project=%+v err=%v", project, err)
	}
	oldView, err := data.SharedProjectForUser(ctx, projectID, owner.ID, true)
	if err != nil || oldView.CurrentRole != "member" {
		t.Fatalf("old owner view=%+v err=%v", oldView, err)
	}
	conversation, err := data.SharedConversationForUser(ctx, conversationID, target.ID)
	if err != nil || conversation.RuntimeOwnerUserID != target.ID || conversation.RuntimeConversationID != "" {
		t.Fatalf("transferred runtime=%+v err=%v", conversation, err)
	}
}
