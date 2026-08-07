package portal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"aionuiportal/internal/instance"
	"aionuiportal/internal/ipc"
	"aionuiportal/internal/modelbootstrap"
	"aionuiportal/internal/portalusage"
	"aionuiportal/internal/store"
)

type sharedRuntimeOptions struct {
	Backend               string            `json:"backend"`
	Models                []string          `json:"models"`
	ThinkingEfforts       []string          `json:"thinking_efforts"`
	DefaultModelID        string            `json:"default_model_id"`
	DefaultThinkingEffort string            `json:"default_thinking_effort"`
	ModelDefaults         map[string]string `json:"model_defaults"`
}

func sharedRuntimeOptionsFor(backend string) (sharedRuntimeOptions, bool) {
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case "codex":
		models := modelbootstrap.ManagedCodexModels()
		defaults := make(map[string]string, len(models))
		for _, model := range models {
			defaults[model] = modelbootstrap.DefaultCodexReasoningEffort
		}
		return sharedRuntimeOptions{Backend: "codex", Models: models, ThinkingEfforts: []string{"low", "medium", "high", "xhigh", "max"}, DefaultModelID: modelbootstrap.DefaultCodexModel, DefaultThinkingEffort: modelbootstrap.DefaultCodexReasoningEffort, ModelDefaults: defaults}, true
	case "kimi":
		rawModels := modelbootstrap.ManagedKimiModels()
		models := make([]string, 0, len(rawModels))
		defaults := make(map[string]string, len(rawModels))
		for _, raw := range rawModels {
			model := "kimi-code/" + raw + ",thinking"
			models = append(models, model)
			if raw == "kimi-k3" {
				defaults[model] = "low"
			} else {
				defaults[model] = "high"
			}
		}
		defaultModel := "kimi-code/kimi-k3,thinking"
		return sharedRuntimeOptions{Backend: "kimi", Models: models, ThinkingEfforts: []string{"low", "high", "max"}, DefaultModelID: defaultModel, DefaultThinkingEffort: defaults[defaultModel], ModelDefaults: defaults}, true
	default:
		return sharedRuntimeOptions{}, false
	}
}

func (o sharedRuntimeOptions) valid(modelID, thinkingEffort string) bool {
	modelOK, effortOK := false, false
	for _, model := range o.Models {
		modelOK = modelOK || model == strings.TrimSpace(modelID)
	}
	for _, effort := range o.ThinkingEfforts {
		effortOK = effortOK || effort == strings.TrimSpace(thinkingEffort)
	}
	return modelOK && effortOK
}

func (s *Server) sharedRuntimeOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if _, _, err := s.session(r); err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	if len(r.URL.Query()) != 1 {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_RUNTIME", "A single backend query is required")
		return
	}
	options, ok := sharedRuntimeOptionsFor(r.URL.Query().Get("backend"))
	if !ok {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_RUNTIME", "Shared runtime backend is not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": options})
}

func (s *Server) sharedProjects(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listSharedProjects(w, r)
	case http.MethodPost:
		s.createSharedProject(w, r)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) listSharedProjects(w http.ResponseWriter, r *http.Request) {
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	includeHidden := false
	if raw := r.URL.Query().Get("include_hidden"); raw != "" {
		if raw != "true" || len(r.URL.Query()) != 1 {
			writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_REQUEST", "Invalid hidden-project query")
			return
		}
		includeHidden = true
	} else if r.URL.RawQuery != "" {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_REQUEST", "Invalid shared-project query")
		return
	}
	projects, err := s.store.ListSharedProjects(r.Context(), session.User.ID, includeHidden)
	if err != nil {
		s.internalError(w, "list shared projects", err)
		return
	}
	items := make([]map[string]any, 0, len(projects))
	for _, project := range projects {
		items = append(items, sharedProjectPayload(project))
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"projects": items}})
}

func (s *Server) createSharedProject(w http.ResponseWriter, r *http.Request) {
	if !s.validBrowserOrigin(r) {
		writeProjectError(w, http.StatusForbidden, "INVALID_ORIGIN", "Security origin validation failed")
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	if r.URL.RawQuery != "" {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_REQUEST", "Shared-project creation does not accept query parameters")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
	var request struct {
		Name            string `json:"name"`
		SourceKind      string `json:"source_kind"`
		SourceProjectID string `json:"source_project_id,omitempty"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_REQUEST", "Invalid shared-project request")
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	request.SourceProjectID = strings.TrimSpace(request.SourceProjectID)
	if request.Name == "" || len(request.Name) > 128 || (request.SourceKind != "new" && request.SourceKind != "copy" && request.SourceKind != "migrate") || (request.SourceKind == "new") != (request.SourceProjectID == "") {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_REQUEST", "Shared-project fields are invalid")
		return
	}
	projectID, err := store.NewStableID()
	if err != nil {
		s.internalError(w, "create shared project id", err)
		return
	}
	now := s.now()
	project, err := s.store.CreateSharedProject(r.Context(), store.SharedProject{ID: projectID, OwnerUserID: session.User.ID, Name: request.Name, SourceKind: request.SourceKind}, now)
	if err != nil {
		s.internalError(w, "reserve shared project", err)
		return
	}
	rootMembers, err := s.store.SharedOwnerRootMemberSIDs(r.Context(), session.User.ID)
	if err != nil {
		_ = s.store.AbortSharedProjectProvisioning(r.Context(), projectID)
		s.internalError(w, "resolve shared owner-root members", err)
		return
	}
	result, err := s.instances.ProvisionSharedProject(r.Context(), session.User.WindowsSID, ipc.SharedProjectRequest{
		ProjectID: projectID, SourceKind: request.SourceKind, SourceProjectID: request.SourceProjectID,
		ProjectMemberSIDs: nil, OwnerRootMemberSIDs: rootMembers,
	})
	if err != nil {
		_ = s.store.AbortSharedProjectProvisioning(r.Context(), projectID)
		var commandError *instance.UserHostCommandError
		if errors.As(err, &commandError) {
			status := http.StatusServiceUnavailable
			if commandError.Code == "SHARED_QUOTA_EXCEEDED" {
				status = http.StatusInsufficientStorage
			} else if commandError.Code == "PROJECT_IN_USE" || commandError.Code == "SHARED_PROJECT_EXISTS" {
				status = http.StatusConflict
			}
			writeProjectError(w, status, commandError.Code, "Shared project could not be created")
			return
		}
		s.logger.Printf("shared project provisioning failed sid=%s project=%s: %v", session.User.WindowsSID, projectID, err)
		writeProjectError(w, http.StatusServiceUnavailable, "SHARED_PROJECT_FAILED", "Shared project could not be created")
		return
	}
	if result.ProjectID != projectID {
		_ = s.instances.FinishSharedProjectProvisioning(r.Context(), session.User.WindowsSID, ipc.SharedProjectRequest{ProjectID: projectID, SourceKind: request.SourceKind}, false)
		_ = s.store.AbortSharedProjectProvisioning(r.Context(), projectID)
		writeProjectError(w, http.StatusServiceUnavailable, "SHARED_PROJECT_FAILED", "Shared project result did not match its reservation")
		return
	}
	if err := s.store.SetSharedProjectProvisioningResult(r.Context(), projectID, true, s.now()); err != nil {
		rollbackErr := s.instances.FinishSharedProjectProvisioning(r.Context(), session.User.WindowsSID, ipc.SharedProjectRequest{ProjectID: projectID, SourceKind: request.SourceKind}, false)
		if rollbackErr == nil {
			_ = s.store.AbortSharedProjectProvisioning(r.Context(), projectID)
		} else {
			s.logger.Printf("critical: shared project activation and filesystem rollback both failed sid=%s project=%s: activation=%v rollback=%v", session.User.WindowsSID, projectID, err, rollbackErr)
		}
		s.internalError(w, "activate shared project", err)
		return
	}
	if err := s.instances.FinishSharedProjectProvisioning(r.Context(), session.User.WindowsSID, ipc.SharedProjectRequest{ProjectID: projectID, SourceKind: request.SourceKind}, true); err != nil {
		revertErr := s.store.RevertSharedProjectActivation(r.Context(), projectID, s.now())
		rollbackErr := s.instances.FinishSharedProjectProvisioning(r.Context(), session.User.WindowsSID, ipc.SharedProjectRequest{ProjectID: projectID, SourceKind: request.SourceKind}, false)
		if revertErr == nil && rollbackErr == nil {
			_ = s.store.AbortSharedProjectProvisioning(r.Context(), projectID)
		} else {
			s.logger.Printf("critical: shared project finalization rollback incomplete sid=%s project=%s: finalize=%v db_revert=%v filesystem_rollback=%v", session.User.WindowsSID, projectID, err, revertErr, rollbackErr)
		}
		writeProjectError(w, http.StatusServiceUnavailable, "SHARED_PROJECT_FINALIZE_FAILED", "Shared project could not be finalized")
		return
	}
	project, err = s.store.SharedProjectForUser(r.Context(), projectID, session.User.ID, true)
	if err != nil {
		s.internalError(w, "read activated shared project", err)
		return
	}
	s.auditBestEffort(r.Context(), "portal.shared_project.create", "success", session, r, map[string]any{"project_id": projectID, "source_kind": request.SourceKind, "size_bytes": result.SizeBytes})
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "data": map[string]any{"project": sharedProjectPayload(project)}})
}

func (s *Server) sharedProjectHidden(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeProjectError(w, http.StatusForbidden, "INVALID_ORIGIN", "Security origin validation failed")
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	var request struct {
		ProjectID string `json:"project_id"`
		Hidden    bool   `json:"hidden"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_REQUEST", "Invalid hidden-project request")
		return
	}
	if _, err := s.store.SharedProjectForUser(r.Context(), request.ProjectID, session.User.ID, true); err != nil {
		writeProjectError(w, http.StatusNotFound, "SHARED_PROJECT_NOT_FOUND", "Shared project was not found")
		return
	}
	if err := s.store.SetSharedItemHidden(r.Context(), session.User.ID, "project", request.ProjectID, request.Hidden, s.now()); err != nil {
		s.internalError(w, "set shared project hidden", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) sharedProjectTransfer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeProjectError(w, http.StatusForbidden, "INVALID_ORIGIN", "Security origin validation failed")
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	var request struct {
		ProjectID      string `json:"project_id"`
		NewOwnerUserID int64  `json:"new_owner_user_id"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || request.NewOwnerUserID <= 0 {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_TRANSFER", "Invalid ownership transfer request")
		return
	}
	project, err := s.store.SharedProjectForUser(r.Context(), request.ProjectID, session.User.ID, true)
	if err != nil || project.CurrentRole != "owner" {
		writeProjectError(w, http.StatusForbidden, "SHARED_TRANSFER_FORBIDDEN", "Only the current owner can transfer ownership")
		return
	}
	conversations, err := s.store.ListSharedConversations(r.Context(), session.User.ID)
	if err != nil {
		s.internalError(w, "list conversations before ownership transfer", err)
		return
	}
	for _, conversation := range conversations {
		if conversation.ProjectID != project.ID || conversation.State != "running" {
			continue
		}
		if err := s.instances.StopSharedAgent(r.Context(), session.User.WindowsSID, ipc.SharedAgentStopRequest{ProjectID: project.ID}); err != nil {
			writeProjectError(w, http.StatusConflict, "PROJECT_IN_USE", "Project tasks could not be stopped for ownership transfer")
			return
		}
		stoppedRun, stopErr := s.store.StopSharedAIRun(r.Context(), conversation.ID, session.User.ID, s.now())
		if stopErr != nil && !errors.Is(stopErr, store.ErrNotFound) {
			s.internalError(w, "settle transfer stop", stopErr)
			return
		}
		if stopErr == nil {
			s.publishSharedMessagesAfter(session.User.ID, conversation.ID, stoppedRun.ContextThroughSeq)
		}
	}
	project, err = s.store.BeginSharedOwnershipTransfer(r.Context(), project.ID, request.NewOwnerUserID, session.User.ID, s.now())
	if err != nil {
		writeProjectError(w, http.StatusConflict, "SHARED_TRANSFER_CONFLICT", "Ownership transfer could not be reserved")
		return
	}
	rollbackDB := func() {
		_ = s.store.FinishSharedOwnershipTransfer(context.Background(), project.ID, session.User.ID, request.NewOwnerUserID, false, s.now())
	}
	newOwner, err := s.store.UserByID(r.Context(), request.NewOwnerUserID)
	if err != nil {
		rollbackDB()
		writeProjectError(w, http.StatusBadRequest, "SHARED_TRANSFER_TARGET_INVALID", "New owner was not found")
		return
	}
	members, err := s.store.SharedProjectMembers(r.Context(), project.ID, session.User.ID)
	if err != nil {
		rollbackDB()
		s.internalError(w, "list transfer members", err)
		return
	}
	newProjectMembers, oldProjectMembers := []string{}, []string{}
	rootMembers, err := s.store.SharedOwnerRootMemberSIDs(r.Context(), newOwner.ID)
	if err != nil {
		rollbackDB()
		s.internalError(w, "list new owner shared-root members", err)
		return
	}
	previousRootMembers := append([]string(nil), rootMembers...)
	for _, member := range members {
		if member.UserID != newOwner.ID {
			newProjectMembers = append(newProjectMembers, member.WindowsSID)
			rootMembers = append(rootMembers, member.WindowsSID)
		}
		if member.UserID != session.User.ID {
			oldProjectMembers = append(oldProjectMembers, member.WindowsSID)
		}
	}
	rootMembers = uniqueSIDs(rootMembers)
	transfer := ipc.SharedTransferRequest{ProjectID: project.ID, OldOwnerSID: session.User.WindowsSID, ProjectMemberSIDs: newProjectMembers, OldProjectMemberSIDs: oldProjectMembers, OwnerRootMemberSIDs: rootMembers, PreviousOwnerRootMemberSIDs: previousRootMembers}
	relocation := ipc.SharedConversationRelocateRequest{ProjectID: project.ID, OldOwnerSID: session.User.WindowsSID, NewOwnerSID: newOwner.WindowsSID}
	memberSIDs := make([]string, 0, len(members))
	for _, member := range members {
		memberSIDs = append(memberSIDs, member.WindowsSID)
	}
	memberSIDs = uniqueSIDs(memberSIDs)
	preparedSIDs := make([]string, 0, len(memberSIDs))
	rollbackRelocations := func() error {
		var joined error
		for _, sid := range preparedSIDs {
			relocation.Phase = "rollback"
			if relocateErr := s.instances.RelocateSharedProjectConversations(context.Background(), sid, relocation); relocateErr != nil {
				joined = errors.Join(joined, fmt.Errorf("rollback %s: %w", sid, relocateErr))
			}
		}
		return joined
	}
	for _, sid := range memberSIDs {
		relocation.Phase = "prepare"
		if err := s.instances.RelocateSharedProjectConversations(r.Context(), sid, relocation); err != nil {
			rollbackErr := rollbackRelocations()
			rollbackDB()
			if rollbackErr != nil {
				s.logger.Printf("critical: shared conversation prepare rollback diverged project=%s: prepare=%v rollback=%v", project.ID, err, rollbackErr)
			}
			writeProjectError(w, http.StatusConflict, "PROJECT_IN_USE", "Member conversations could not be stopped for ownership transfer")
			return
		}
		preparedSIDs = append(preparedSIDs, sid)
	}
	if err := s.instances.TransferSharedProject(r.Context(), newOwner.WindowsSID, transfer); err != nil {
		rollbackErr := rollbackRelocations()
		rollbackDB()
		if rollbackErr != nil {
			s.logger.Printf("critical: transfer prepare rollback diverged project=%s: transfer=%v rollback=%v", project.ID, err, rollbackErr)
		}
		var commandError *instance.UserHostCommandError
		if errors.As(err, &commandError) && commandError.Code == "SHARED_QUOTA_EXCEEDED" {
			writeProjectError(w, http.StatusInsufficientStorage, commandError.Code, "New owner does not have enough shared space")
			return
		}
		writeProjectError(w, http.StatusServiceUnavailable, "SHARED_TRANSFER_FAILED", "Shared project could not be moved to the new owner")
		return
	}
	for _, sid := range preparedSIDs {
		relocation.Phase = "commit"
		if err := s.instances.RelocateSharedProjectConversations(r.Context(), sid, relocation); err != nil {
			filesystemRollbackErr := s.instances.FinishSharedProjectTransfer(context.Background(), newOwner.WindowsSID, transfer, false)
			if filesystemRollbackErr != nil {
				s.logger.Printf("critical: ownership transfer filesystem rollback failed project=%s relocation=%v fs=%v", project.ID, err, filesystemRollbackErr)
				writeProjectError(w, http.StatusServiceUnavailable, "SHARED_TRANSFER_ROLLBACK_FAILED", "Ownership transfer requires administrator recovery")
				return
			}
			relocationRollbackErr := rollbackRelocations()
			rollbackDB()
			if relocationRollbackErr != nil {
				s.logger.Printf("critical: ownership transfer conversation rollback diverged project=%s relocation=%v rollback=%v", project.ID, err, relocationRollbackErr)
			}
			writeProjectError(w, http.StatusServiceUnavailable, "SHARED_TRANSFER_RESUME_FAILED", "Member conversations could not be resumed after ownership transfer")
			return
		}
	}
	if err := s.store.FinishSharedOwnershipTransfer(r.Context(), project.ID, session.User.ID, newOwner.ID, true, s.now()); err != nil {
		rollbackErr := s.instances.FinishSharedProjectTransfer(context.Background(), newOwner.WindowsSID, transfer, false)
		if rollbackErr != nil {
			s.logger.Printf("critical: ownership transfer database and filesystem rollback diverged project=%s: db=%v fs=%v", project.ID, err, rollbackErr)
			writeProjectError(w, http.StatusServiceUnavailable, "SHARED_TRANSFER_ROLLBACK_FAILED", "Ownership transfer requires administrator recovery")
			return
		}
		relocationRollbackErr := rollbackRelocations()
		rollbackDB()
		if relocationRollbackErr != nil {
			s.logger.Printf("critical: ownership transfer database and conversation rollback diverged project=%s: db=%v conversations=%v", project.ID, err, relocationRollbackErr)
		}
		s.internalError(w, "commit shared ownership transfer", err)
		return
	}
	if err := s.instances.FinishSharedProjectTransfer(r.Context(), newOwner.WindowsSID, transfer, true); err != nil {
		s.logger.Printf("ownership transfer committed with recoverable journal project=%s new_owner=%d: %v", project.ID, newOwner.ID, err)
	}
	for _, sid := range preparedSIDs {
		relocation.Phase = "finish"
		if err := s.instances.RelocateSharedProjectConversations(r.Context(), sid, relocation); err != nil {
			s.logger.Printf("ownership transfer committed with recoverable conversation journal project=%s member_sid=%s: %v", project.ID, sid, err)
		}
	}
	project, err = s.store.SharedProjectForUser(r.Context(), project.ID, session.User.ID, true)
	if err != nil {
		s.internalError(w, "read transferred shared project", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"project": sharedProjectPayload(project)}})
}

func uniqueSIDs(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		key := strings.ToUpper(strings.TrimSpace(value))
		if key != "" && !seen[key] {
			seen[key] = true
			result = append(result, strings.TrimSpace(value))
		}
	}
	return result
}

func (s *Server) sharedConversations(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.listSharedConversations(w, r)
		return
	}
	if r.Method == http.MethodPatch {
		s.updateSharedConversation(w, r)
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeProjectError(w, http.StatusForbidden, "INVALID_ORIGIN", "Security origin validation failed")
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	var request struct {
		ProjectID string `json:"project_id"`
		Name      string `json:"name"`
		Assistant string `json:"assistant_id"`
		Backend   string `json:"assistant_backend"`
		Model     string `json:"model_id"`
		Thinking  string `json:"thinking_effort"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_CONVERSATION", "Invalid shared conversation request")
		return
	}
	id, err := store.NewStableID()
	if err != nil {
		s.internalError(w, "create shared conversation id", err)
		return
	}
	options, valid := sharedRuntimeOptionsFor(request.Backend)
	request.Thinking = strings.TrimSpace(request.Thinking)
	if request.Thinking == "" {
		request.Thinking = options.ModelDefaults[strings.TrimSpace(request.Model)]
	}
	if !valid || !options.valid(request.Model, request.Thinking) {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_RUNTIME", "Shared runtime model or thinking effort is not allowed")
		return
	}
	conversation, err := s.store.CreateSharedConversation(r.Context(), store.SharedConversation{ID: id, ProjectID: request.ProjectID, Name: request.Name, AssistantID: request.Assistant, AssistantBackend: request.Backend, ModelID: request.Model, ThinkingEffort: request.Thinking}, session.User.ID, s.now())
	if errors.Is(err, store.ErrForbidden) || errors.Is(err, store.ErrNotFound) {
		writeProjectError(w, http.StatusForbidden, "SHARED_PROJECT_FORBIDDEN", "Only an accepted shared project member can create a conversation")
		return
	}
	if err != nil {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_CONVERSATION", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "data": map[string]any{"conversation": sharedConversationPayload(conversation)}})
}

func (s *Server) updateSharedConversation(w http.ResponseWriter, r *http.Request) {
	if !s.validBrowserOrigin(r) {
		writeProjectError(w, http.StatusForbidden, "INVALID_ORIGIN", "Security origin validation failed")
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	var request struct {
		ConversationID string  `json:"conversation_id"`
		ModelID        string  `json:"model_id,omitempty"`
		ThinkingEffort string  `json:"thinking_effort,omitempty"`
		Stop           bool    `json:"stop,omitempty"`
		Name           *string `json:"name,omitempty"`
		Pinned         *bool   `json:"pinned,omitempty"`
		Hidden         *bool   `json:"hidden,omitempty"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_CONVERSATION", "Specify exactly one shared-conversation operation")
		return
	}
	operationCount := 0
	if request.Stop {
		operationCount++
	}
	if strings.TrimSpace(request.ModelID) != "" || strings.TrimSpace(request.ThinkingEffort) != "" {
		operationCount++
	}
	if request.Name != nil {
		operationCount++
	}
	if request.Pinned != nil {
		operationCount++
	}
	if request.Hidden != nil {
		operationCount++
	}
	if operationCount != 1 {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_CONVERSATION", "Specify exactly one shared-conversation operation")
		return
	}
	conversation, err := s.store.SharedConversationForUser(r.Context(), request.ConversationID, session.User.ID)
	if err != nil {
		writeProjectError(w, http.StatusNotFound, "SHARED_CONVERSATION_NOT_FOUND", "Shared conversation was not found")
		return
	}
	if request.Stop {
		if conversation.State != "running" {
			writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"conversation": sharedConversationPayload(conversation)}})
			return
		}
		owner, err := s.store.UserByID(r.Context(), conversation.RuntimeOwnerUserID)
		if err != nil {
			s.internalError(w, "resolve shared runtime owner", err)
			return
		}
		if err := s.instances.StopSharedAgent(r.Context(), owner.WindowsSID, ipc.SharedAgentStopRequest{ProjectID: conversation.ProjectID}); err != nil {
			writeProjectError(w, http.StatusServiceUnavailable, "SHARED_AGENT_STOP_FAILED", "Shared AI could not be stopped")
			return
		}
		stoppedRun, stopErr := s.store.StopSharedAIRun(r.Context(), conversation.ID, session.User.ID, s.now())
		if stopErr != nil && !errors.Is(stopErr, store.ErrNotFound) {
			s.internalError(w, "settle stopped shared AI run", stopErr)
			return
		}
		if stopErr == nil {
			s.publishSharedMessagesAfter(session.User.ID, conversation.ID, stoppedRun.ContextThroughSeq)
		}
		conversation, err = s.store.SharedConversationForUser(r.Context(), conversation.ID, session.User.ID)
		if err != nil {
			s.internalError(w, "read stopped shared conversation", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"conversation": sharedConversationPayload(conversation)}})
		return
	}
	if request.Name != nil || request.Pinned != nil || request.Hidden != nil {
		conversation, err = s.store.UpdateSharedConversationMetadata(r.Context(), conversation.ID, session.User.ID, request.Name, request.Pinned, request.Hidden, s.now())
	} else {
		modelID, thinkingEffort := strings.TrimSpace(request.ModelID), strings.TrimSpace(request.ThinkingEffort)
		if modelID == "" {
			modelID = conversation.ModelID
		}
		if thinkingEffort == "" {
			thinkingEffort = conversation.ThinkingEffort
		}
		options, valid := sharedRuntimeOptionsFor(conversation.AssistantBackend)
		if !valid || !options.valid(modelID, thinkingEffort) {
			writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_RUNTIME", "Shared runtime model or thinking effort is not allowed")
			return
		}
		conversation, err = s.store.UpdateSharedConversationRuntime(r.Context(), conversation.ID, session.User.ID, modelID, thinkingEffort, s.now())
	}
	if errors.Is(err, store.ErrConflict) {
		writeProjectError(w, http.StatusConflict, "SHARED_CONVERSATION_BUSY", "Stop the current AI run before switching model")
		return
	}
	if err != nil {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_CONVERSATION", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"conversation": sharedConversationPayload(conversation)}})
}

func (s *Server) listSharedConversations(w http.ResponseWriter, r *http.Request) {
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	if id := strings.TrimSpace(r.URL.Query().Get("id")); id != "" {
		if len(r.URL.Query()) != 1 {
			writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_CONVERSATION", "Invalid shared conversation query")
			return
		}
		conversation, err := s.store.SharedConversationForUser(r.Context(), id, session.User.ID)
		if err != nil {
			writeProjectError(w, http.StatusNotFound, "SHARED_CONVERSATION_NOT_FOUND", "Shared conversation was not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"conversation": sharedConversationPayload(conversation)}})
		return
	}
	if r.URL.RawQuery != "" && r.URL.RawQuery != "include_hidden=1" {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_CONVERSATION", "Invalid shared conversation query")
		return
	}
	includeHidden := r.URL.Query().Get("include_hidden") == "1"
	var conversations []store.SharedConversation
	if includeHidden {
		conversations, err = s.store.ListAllSharedConversations(r.Context(), session.User.ID)
	} else {
		conversations, err = s.store.ListSharedConversations(r.Context(), session.User.ID)
	}
	if err != nil {
		s.internalError(w, "list shared conversations", err)
		return
	}
	items := make([]map[string]any, 0, len(conversations))
	for _, conversation := range conversations {
		items = append(items, sharedConversationPayload(conversation))
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"conversations": items}})
}

func (s *Server) sharedMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.listSharedMessages(w, r)
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeProjectError(w, http.StatusForbidden, "INVALID_ORIGIN", "Security origin validation failed")
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	var request struct {
		ConversationID string                `json:"conversation_id"`
		Body           string                `json:"body"`
		Mentions       []store.SharedMention `json:"mentions"`
		Attachments    []string              `json:"attachments"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 160*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_MESSAGE", "Invalid shared message request")
		return
	}
	id, err := store.NewStableID()
	if err != nil {
		s.internalError(w, "create shared message id", err)
		return
	}
	message, err := s.store.AddSharedMessage(r.Context(), store.SharedMessage{ID: id, Conversation: request.ConversationID, AuthorUserID: &session.User.ID, Kind: "user", Body: request.Body, Mentions: request.Mentions, Attachments: request.Attachments}, s.now())
	if err != nil {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_MESSAGE", err.Error())
		return
	}
	s.publishSharedMessage(message)
	aiStarted := s.maybeStartSharedAI(r.Context(), message, session.User.ID)
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "data": map[string]any{"message": sharedMessagePayload(message, session.User.ID), "ai_started": aiStarted}})
}

func (s *Server) maybeStartSharedAI(ctx context.Context, message store.SharedMessage, requesterUserID int64) bool {
	conversation, err := s.store.SharedConversationForUser(ctx, message.Conversation, requesterUserID)
	if err != nil {
		return false
	}
	trigger := false
	for _, mention := range message.Mentions {
		if mention.Kind == "assistant" && mention.ID == conversation.AssistantID {
			trigger = true
			break
		}
	}
	if !trigger {
		return false
	}
	members, err := s.store.SharedProjectMembers(ctx, conversation.ProjectID, requesterUserID)
	if err != nil {
		return false
	}
	sids := make([]string, 0, len(members))
	for _, member := range members {
		sids = append(sids, member.WindowsSID)
	}
	summaries, err := s.usage.CurrentMany(ctx, sids)
	if err != nil {
		s.addSharedSystemMessageAndPublish(ctx, conversation.ID, requesterUserID, message.Seq, "AI quota could not be verified; no AI run was started.")
		return false
	}
	payers := make([]store.SharedAIRunPayer, 0, len(members))
	providerKind := portalusage.KindChatGPT
	if conversation.AssistantBackend == "kimi" {
		providerKind = portalusage.KindKimi
	}
	for _, member := range members {
		summary, ok := summaries[strings.ToUpper(member.WindowsSID)]
		if !ok || !providerHasQuota(summary, providerKind) {
			continue
		}
		ids := modelbootstrap.KeyIDsForSID(member.WindowsSID)
		keyID := ids.CodexKeyID
		if conversation.AssistantBackend == "kimi" {
			keyID = ids.KimiKeyID
		}
		payers = append(payers, store.SharedAIRunPayer{UserID: member.UserID, KeyID: keyID})
	}
	if len(payers) == 0 {
		s.addSharedSystemMessageAndPublish(ctx, conversation.ID, requesterUserID, message.Seq, "No current member has available quota, so the AI was not started.")
		return false
	}
	runID, err := store.NewStableID()
	if err != nil {
		return false
	}
	run, err := s.store.ReserveSharedAIRun(ctx, runID, message, conversation.AssistantBackend, payers, s.now())
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.addSharedSystemMessageAndPublish(ctx, conversation.ID, requesterUserID, message.Seq, "An AI run is already active; this message remains in the next shared context.")
		}
		return false
	}
	deltaMessages, err := s.store.SharedUserMessagesRange(ctx, conversation.ID, run.ContextFromSeq, run.ContextThroughSeq)
	if err != nil {
		_ = s.store.FinishSharedAIRun(ctx, run, "", "", false, err, s.now())
		return false
	}
	fullMessages, err := s.store.SharedUserMessagesRange(ctx, conversation.ID, 0, run.ContextThroughSeq)
	if err != nil {
		_ = s.store.FinishSharedAIRun(ctx, run, "", "", false, err, s.now())
		return false
	}
	contextBody := formatSharedAIContext(deltaMessages)
	recoveryBody := formatSharedAIContext(fullMessages)
	if len(contextBody) > 512*1024 || len(recoveryBody) > 768*1024 {
		err := errors.New("shared AI context exceeded the bounded IPC size")
		_ = s.store.FinishSharedAIRun(ctx, run, "", "", false, err, s.now())
		return false
	}
	owner, err := s.store.UserByID(ctx, run.OwnerUserID)
	if err != nil {
		_ = s.store.FinishSharedAIRun(ctx, run, "", "", false, err, s.now())
		return false
	}
	payerKeyIDs := make([]string, 0, len(payers))
	for _, payer := range payers {
		payerKeyIDs = append(payerKeyIDs, payer.KeyID)
	}
	go s.executeSharedAI(run, conversation, owner.WindowsSID, payerKeyIDs, contextBody, recoveryBody)
	return true
}

func providerHasQuota(summary portalusage.Summary, kind string) bool {
	for _, provider := range summary.Providers {
		if provider.Kind != kind {
			continue
		}
		daily, dailyOK := new(big.Rat).SetString(provider.Daily.RemainingUSD)
		weekly, weeklyOK := new(big.Rat).SetString(provider.Weekly.RemainingUSD)
		return dailyOK && weeklyOK && daily.Sign() > 0 && weekly.Sign() > 0
	}
	return false
}

func (s *Server) addSharedSystemMessageAndPublish(ctx context.Context, conversationID string, userID, afterSeq int64, body string) {
	if err := s.store.AddSharedSystemMessage(ctx, conversationID, body, s.now()); err == nil {
		s.publishSharedMessagesAfter(userID, conversationID, afterSeq)
	}
}

func formatSharedAIContext(messages []store.SharedMessage) string {
	var builder strings.Builder
	builder.WriteString("Shared project group conversation. Treat each bracketed author as a distinct human participant and use the shared workspace.\n\n")
	for _, item := range messages {
		builder.WriteString("[")
		builder.WriteString(item.AuthorName)
		if item.AuthorUserID != nil {
			builder.WriteString(" user:")
			builder.WriteString(strconv.FormatInt(*item.AuthorUserID, 10))
		}
		builder.WriteString("]\n")
		builder.WriteString(item.Body)
		for _, attachment := range item.Attachments {
			builder.WriteString("\n[attachment:")
			builder.WriteString(attachment)
			builder.WriteString("]")
		}
		builder.WriteString("\n\n")
	}
	return builder.String()
}

func (s *Server) executeSharedAI(run store.SharedAIRun, conversation store.SharedConversation, ownerSID string, payerKeyIDs []string, contextBody, recoveryBody string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	credentialID, err := s.ensureSharedAgentCredential(ctx, ownerSID, conversation.ID, payerKeyIDs)
	if err != nil {
		if finishErr := s.store.FinishSharedAIRun(context.Background(), run, "", "", false, err, s.now()); finishErr != nil {
			s.logger.Printf("critical: shared AI credential failure settlement failed run=%s conversation=%s: %v", run.ID, run.ConversationID, finishErr)
			return
		}
		s.publishSharedMessagesAfter(run.OwnerUserID, run.ConversationID, run.ContextThroughSeq)
		return
	}
	result, err := s.instances.RunSharedAgent(ctx, ownerSID, ipc.SharedAgentRequest{
		ProjectID: conversation.ProjectID, RuntimeConversationID: conversation.RuntimeConversationID,
		Name: conversation.Name, AssistantID: conversation.AssistantID, AssistantBackend: conversation.AssistantBackend,
		ModelID: conversation.ModelID, ThinkingEffort: conversation.ThinkingEffort, Context: contextBody, RecoveryContext: recoveryBody, CredentialID: credentialID,
	})
	runtimeID, body, recovered := result.RuntimeConversationID, result.AssistantBody, result.Recovered
	if finishErr := s.store.FinishSharedAIRun(context.Background(), run, runtimeID, body, recovered, err, s.now()); finishErr != nil {
		s.logger.Printf("critical: shared AI run settlement failed run=%s conversation=%s: %v", run.ID, run.ConversationID, finishErr)
		return
	}
	s.publishSharedMessagesAfter(run.OwnerUserID, run.ConversationID, run.ContextThroughSeq)
}

func (s *Server) listSharedMessages(w http.ResponseWriter, r *http.Request) {
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	conversationID := strings.TrimSpace(r.URL.Query().Get("conversation_id"))
	after, limit := int64(0), 100
	if raw := r.URL.Query().Get("after"); raw != "" {
		after, err = strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_CURSOR", "Shared message cursor is invalid")
			return
		}
	}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil {
			writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_CURSOR", "Shared message limit is invalid")
			return
		}
	}
	if conversationID == "" || len(r.URL.Query()) > 3 {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_CURSOR", "Shared conversation id is required")
		return
	}
	messages, err := s.store.ListSharedMessages(r.Context(), conversationID, session.User.ID, after, limit)
	if err != nil {
		writeProjectError(w, http.StatusNotFound, "SHARED_CONVERSATION_NOT_FOUND", "Shared conversation was not found")
		return
	}
	items := make([]map[string]any, 0, len(messages))
	for _, message := range messages {
		items = append(items, sharedMessagePayload(message, session.User.ID))
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"messages": items}})
}

func sharedProjectPayload(project store.SharedProject) map[string]any {
	return map[string]any{
		"id": project.ID, "name": project.Name, "source_kind": project.SourceKind, "state": project.State,
		"role": project.CurrentRole, "owner_name": project.OwnerName, "member_count": project.MemberCount, "hidden": project.Hidden,
		"created_at": project.CreatedAt, "updated_at": project.UpdatedAt,
	}
}

func (s *Server) sharedUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	if len(r.URL.Query()) != 1 || r.URL.Query().Get("q") == "" {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_USER_QUERY", "A user query is required")
		return
	}
	users, err := s.store.SearchSharedUsers(r.Context(), session.User.ID, r.URL.Query().Get("q"), 20)
	if err != nil {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_USER_QUERY", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(users))
	for _, user := range users {
		items = append(items, map[string]any{"id": user.ID, "username": user.Username, "display_name": user.DisplayName})
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"users": items}})
}

func (s *Server) sharedMembers(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		s.removeSharedMember(w, r)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if projectID == "" || len(r.URL.Query()) != 1 {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_PROJECT", "Shared project id is required")
		return
	}
	members, err := s.store.SharedProjectMembers(r.Context(), projectID, session.User.ID)
	if err != nil {
		writeProjectError(w, http.StatusNotFound, "SHARED_PROJECT_NOT_FOUND", "Shared project was not found")
		return
	}
	items := make([]map[string]any, 0, len(members))
	for _, member := range members {
		items = append(items, map[string]any{"id": member.UserID, "username": member.Username, "display_name": member.DisplayName, "role": member.Role})
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"members": items}})
}

func (s *Server) removeSharedMember(w http.ResponseWriter, r *http.Request) {
	if !s.validBrowserOrigin(r) {
		writeProjectError(w, http.StatusForbidden, "INVALID_ORIGIN", "Security origin validation failed")
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	if r.URL.RawQuery != "" {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_MEMBER", "Shared member removal does not accept query parameters")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var request struct {
		ProjectID string `json:"project_id"`
		UserID    int64  `json:"user_id"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF || strings.TrimSpace(request.ProjectID) == "" || request.UserID <= 0 {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_MEMBER", "Shared member fields are invalid")
		return
	}
	project, err := s.store.BeginRemoveSharedMember(r.Context(), request.ProjectID, request.UserID, session.User.ID, s.now())
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, store.ErrForbidden) {
			status = http.StatusForbidden
		} else if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeProjectError(w, status, "SHARED_MEMBER_REMOVE_FAILED", "Shared member cannot be removed")
		return
	}
	if err := s.reconcileSharedProjectACL(r.Context(), project); err != nil {
		_ = s.store.FinishRemoveSharedMember(r.Context(), project.ID, request.UserID, false, s.now())
		writeProjectError(w, http.StatusServiceUnavailable, "SHARED_ACL_FAILED", "Shared project access could not be revoked")
		return
	}
	if err := s.store.FinishRemoveSharedMember(r.Context(), project.ID, request.UserID, true, s.now()); err != nil {
		s.internalError(w, "finish shared member removal", err)
		return
	}
	s.auditBestEffort(r.Context(), "portal.shared_member.remove", "success", session, r, map[string]any{"project_id": project.ID, "target_user_id": request.UserID})
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) leaveSharedProject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeProjectError(w, http.StatusForbidden, "INVALID_ORIGIN", "Security origin validation failed")
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	var request struct {
		ProjectID string `json:"project_id"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || strings.TrimSpace(request.ProjectID) == "" {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_MEMBER", "Shared project id is required")
		return
	}
	project, err := s.store.BeginRemoveSharedMember(r.Context(), request.ProjectID, session.User.ID, session.User.ID, s.now())
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, store.ErrForbidden) {
			status = http.StatusForbidden
		}
		writeProjectError(w, status, "SHARED_PROJECT_LEAVE_FAILED", "Transfer ownership before leaving an owned shared project")
		return
	}
	if err := s.reconcileSharedProjectACL(r.Context(), project); err != nil {
		_ = s.store.FinishRemoveSharedMember(r.Context(), project.ID, session.User.ID, false, s.now())
		writeProjectError(w, http.StatusServiceUnavailable, "SHARED_ACL_FAILED", "Shared project access could not be revoked")
		return
	}
	if err := s.store.FinishRemoveSharedMember(r.Context(), project.ID, session.User.ID, true, s.now()); err != nil {
		// Restore database membership and ACL together when finalization fails.
		_ = s.store.FinishRemoveSharedMember(r.Context(), project.ID, session.User.ID, false, s.now())
		_ = s.reconcileSharedProjectACL(r.Context(), project)
		s.internalError(w, "finish shared project leave", err)
		return
	}
	s.auditBestEffort(r.Context(), "portal.shared_project.leave", "success", session, r, map[string]any{"project_id": project.ID})
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) sharedInvites(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		session, _, err := s.session(r)
		if err != nil {
			writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
			return
		}
		if r.URL.RawQuery != "" {
			writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_INVITE", "Shared invite listing does not accept query parameters")
			return
		}
		invites, err := s.store.ListPendingSharedInvites(r.Context(), session.User.ID, s.now())
		if err != nil {
			s.internalError(w, "list pending shared invites", err)
			return
		}
		items := make([]map[string]any, 0, len(invites))
		for _, invite := range invites {
			items = append(items, sharedInvitePayload(invite))
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"invites": items}})
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeProjectError(w, http.StatusForbidden, "INVALID_ORIGIN", "Security origin validation failed")
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	var request struct {
		ProjectID    string `json:"project_id"`
		TargetUserID int64  `json:"target_user_id"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_INVITE", "Invalid shared invite request")
		return
	}
	id, err := store.NewStableID()
	if err != nil {
		s.internalError(w, "create shared invite id", err)
		return
	}
	invite, err := s.store.CreateSharedInvite(r.Context(), store.SharedInvite{ID: id, ProjectID: request.ProjectID, TargetUserID: request.TargetUserID, ExpiresAt: s.now().Add(7 * 24 * time.Hour)}, session.User.ID, s.now())
	if err != nil {
		status := http.StatusBadRequest
		code := "SHARED_INVITE_FAILED"
		message := "Shared invite could not be created"
		if errors.Is(err, store.ErrForbidden) {
			status = http.StatusForbidden
		} else if errors.Is(err, store.ErrInviteAlreadyPending) {
			status = http.StatusConflict
			code = "SHARED_INVITE_ALREADY_PENDING"
			message = "An invitation is already pending for this user"
		} else if errors.Is(err, store.ErrSharedAlreadyMember) {
			status = http.StatusConflict
			code = "SHARED_MEMBER_ALREADY_EXISTS"
			message = "This user is already a project member"
		}
		writeProjectError(w, status, code, message)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "data": map[string]any{"invite": sharedInvitePayload(invite)}})
}

func (s *Server) acceptSharedInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeProjectError(w, http.StatusForbidden, "INVALID_ORIGIN", "Security origin validation failed")
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	inviteID, ok := decodeInviteAction(w, r)
	if !ok {
		return
	}
	invite, err := s.store.BeginAcceptSharedInvite(r.Context(), inviteID, session.User.ID, s.now())
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		} else if errors.Is(err, store.ErrExpired) {
			status = http.StatusGone
		}
		writeProjectError(w, status, "SHARED_INVITE_NOT_ACCEPTABLE", "Shared invite cannot be accepted")
		return
	}
	project, err := s.store.SharedProjectForUser(r.Context(), invite.ProjectID, invite.InviterUserID, true)
	if err != nil {
		_ = s.store.FinishAcceptSharedInvite(r.Context(), inviteID, session.User.ID, false, s.now())
		s.internalError(w, "read shared invite project", err)
		return
	}
	projectSIDs, err := s.store.SharedProjectACLSIDs(r.Context(), invite.ProjectID, project.OwnerUserID)
	if err == nil {
		var rootSIDs []string
		rootSIDs, err = s.store.SharedOwnerRootMemberSIDs(r.Context(), project.OwnerUserID)
		if err == nil {
			err = s.instances.UpdateSharedProjectACL(r.Context(), project.OwnerSID, ipc.SharedProjectRequest{ProjectID: project.ID, ProjectMemberSIDs: projectSIDs, OwnerRootMemberSIDs: rootSIDs})
		}
	}
	if err != nil {
		if rollbackErr := s.store.FinishAcceptSharedInvite(r.Context(), inviteID, session.User.ID, false, s.now()); rollbackErr != nil {
			s.logger.Printf("critical: could not roll back staged shared invite member project=%s sid=%s: %v", project.ID, session.User.WindowsSID, rollbackErr)
		} else if aclErr := s.reconcileSharedProjectACL(r.Context(), project); aclErr != nil {
			s.logger.Printf("critical: could not revoke staged shared ACL after invite failure project=%s sid=%s: %v", project.ID, session.User.WindowsSID, aclErr)
		}
		writeProjectError(w, http.StatusServiceUnavailable, "SHARED_ACL_FAILED", "Shared project access could not be granted")
		return
	}
	if err := s.store.FinishAcceptSharedInvite(r.Context(), inviteID, session.User.ID, true, s.now()); err != nil {
		// Fail closed: immediately remove the staged principal again if the database
		// cannot commit accepted membership.
		_ = s.store.FinishAcceptSharedInvite(r.Context(), inviteID, session.User.ID, false, s.now())
		if aclErr := s.reconcileSharedProjectACL(r.Context(), project); aclErr != nil {
			s.logger.Printf("critical: could not revoke staged shared ACL after invite commit failure project=%s sid=%s: %v", project.ID, session.User.WindowsSID, aclErr)
		}
		s.internalError(w, "commit shared invite acceptance", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) reconcileSharedProjectACL(ctx context.Context, project store.SharedProject) error {
	projectSIDs, err := s.store.SharedProjectACLSIDs(ctx, project.ID, project.OwnerUserID)
	if err != nil {
		return err
	}
	rootSIDs, err := s.store.SharedOwnerRootMemberSIDs(ctx, project.OwnerUserID)
	if err != nil {
		return err
	}
	return s.instances.UpdateSharedProjectACL(ctx, project.OwnerSID, ipc.SharedProjectRequest{
		ProjectID:           project.ID,
		ProjectMemberSIDs:   projectSIDs,
		OwnerRootMemberSIDs: rootSIDs,
	})
}

func (s *Server) declineSharedInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeProjectError(w, http.StatusForbidden, "INVALID_ORIGIN", "Security origin validation failed")
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	inviteID, ok := decodeInviteAction(w, r)
	if !ok {
		return
	}
	if err := s.store.DeclineSharedInvite(r.Context(), inviteID, session.User.ID, s.now()); err != nil {
		writeProjectError(w, http.StatusConflict, "SHARED_INVITE_NOT_ACTIONABLE", "Shared invite cannot be declined")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func decodeInviteAction(w http.ResponseWriter, r *http.Request) (string, bool) {
	var request struct {
		InviteID string `json:"invite_id"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || strings.TrimSpace(request.InviteID) == "" {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_INVITE", "Invalid shared invite action")
		return "", false
	}
	return strings.TrimSpace(request.InviteID), true
}

func sharedInvitePayload(invite store.SharedInvite) map[string]any {
	return map[string]any{"id": invite.ID, "project_id": invite.ProjectID, "project_name": invite.ProjectName, "inviter_name": invite.InviterName, "target_name": invite.TargetName, "status": invite.Status, "created_at": invite.CreatedAt, "expires_at": invite.ExpiresAt}
}

func (s *Server) sharedInviteLinks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeProjectError(w, http.StatusForbidden, "INVALID_ORIGIN", "Security origin validation failed")
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	var request struct {
		ProjectID string `json:"project_id"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || strings.TrimSpace(request.ProjectID) == "" {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_INVITE_LINK", "Shared project id is required")
		return
	}
	token, err := store.NewStableID()
	if err != nil {
		s.internalError(w, "create shared invite link token", err)
		return
	}
	link, err := s.store.CreateSharedInviteLink(r.Context(), store.SharedInviteLink{Token: token, ProjectID: request.ProjectID, ExpiresAt: s.now().Add(7 * 24 * time.Hour)}, session.User.ID, s.now())
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, store.ErrForbidden) {
			status = http.StatusForbidden
		}
		writeProjectError(w, status, "SHARED_INVITE_LINK_FAILED", "Shared invite link could not be created")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "data": map[string]any{"token": link.Token, "expires_at": link.ExpiresAt}})
}

func (s *Server) acceptSharedInviteLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeProjectError(w, http.StatusForbidden, "INVALID_ORIGIN", "Security origin validation failed")
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	var request struct {
		Token string `json:"token"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || strings.TrimSpace(request.Token) == "" {
		writeProjectError(w, http.StatusBadRequest, "INVALID_SHARED_INVITE_LINK", "Shared invite token is required")
		return
	}
	link, err := s.store.BeginAcceptSharedInviteLink(r.Context(), request.Token, session.User.ID, s.now())
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		} else if errors.Is(err, store.ErrExpired) {
			status = http.StatusGone
		}
		writeProjectError(w, status, "SHARED_INVITE_LINK_NOT_ACCEPTABLE", "Shared invite link cannot be accepted")
		return
	}
	project, err := s.store.SharedProjectForUser(r.Context(), link.ProjectID, link.InviterUserID, true)
	if err == nil {
		err = s.reconcileSharedProjectACL(r.Context(), project)
	}
	if err != nil {
		if rollbackErr := s.store.FinishAcceptSharedInviteLink(r.Context(), link.ProjectID, session.User.ID, false, s.now()); rollbackErr != nil {
			s.logger.Printf("critical: could not roll back staged shared invite link member project=%s sid=%s: %v", project.ID, session.User.WindowsSID, rollbackErr)
		} else if aclErr := s.reconcileSharedProjectACL(r.Context(), project); aclErr != nil {
			s.logger.Printf("critical: could not revoke staged shared ACL after invite link failure project=%s sid=%s: %v", project.ID, session.User.WindowsSID, aclErr)
		}
		writeProjectError(w, http.StatusServiceUnavailable, "SHARED_ACL_FAILED", "Shared project access could not be granted")
		return
	}
	if err := s.store.FinishAcceptSharedInviteLink(r.Context(), link.ProjectID, session.User.ID, true, s.now()); err != nil {
		if rollbackErr := s.store.FinishAcceptSharedInviteLink(r.Context(), link.ProjectID, session.User.ID, false, s.now()); rollbackErr != nil {
			s.logger.Printf("critical: could not roll back shared invite link commit project=%s sid=%s: %v", project.ID, session.User.WindowsSID, rollbackErr)
		} else if aclErr := s.reconcileSharedProjectACL(r.Context(), project); aclErr != nil {
			s.logger.Printf("critical: could not revoke staged shared ACL after invite link commit failure project=%s sid=%s: %v", project.ID, session.User.WindowsSID, aclErr)
		}
		s.internalError(w, "commit shared invite link acceptance", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"project_id": link.ProjectID}})
}

func sharedConversationPayload(conversation store.SharedConversation) map[string]any {
	return map[string]any{
		"id": conversation.ID, "project_id": conversation.ProjectID, "project_name": conversation.ProjectName,
		"role": conversation.CurrentRole, "name": conversation.Name, "assistant_id": conversation.AssistantID,
		"assistant_backend": conversation.AssistantBackend, "model_id": conversation.ModelID, "thinking_effort": conversation.ThinkingEffort, "state": conversation.State,
		"last_ai_message_seq": conversation.LastAIMessageSeq, "pinned": conversation.Pinned, "pinned_at": conversation.PinnedAt,
		"hidden": conversation.Hidden, "created_at": conversation.CreatedAt, "updated_at": conversation.UpdatedAt,
	}
}

func sharedMessagePayload(message store.SharedMessage, currentUserID int64) map[string]any {
	isCurrentUser := message.AuthorUserID != nil && *message.AuthorUserID == currentUserID
	return map[string]any{
		"seq": message.Seq, "id": message.ID, "conversation_id": message.Conversation, "author_user_id": message.AuthorUserID,
		"author_name": message.AuthorName, "kind": message.Kind, "body": message.Body, "mentions": message.Mentions,
		"attachments": message.Attachments, "created_at": message.CreatedAt,
		"is_current_user": isCurrentUser,
	}
}
