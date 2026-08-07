package portal

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"aionuiportal/internal/store"
)

func (s *Server) profile(w http.ResponseWriter, r *http.Request) {
	session, _, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	if session.User.Admin {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Employee profile is required"})
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "profile": profilePayload(session.User)})
		return
	}
	if r.Method != http.MethodPatch {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Security origin validation failed"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
	var request struct {
		DisplayName          string `json:"display_name"`
		CollaborationEnabled bool   `json:"collaboration_enabled"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid profile request"})
		return
	}
	updated, err := s.store.UpdateProfile(r.Context(), session.User.ID, request.DisplayName, request.CollaborationEnabled, s.now())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": err.Error()})
		return
	}
	if err := s.audit(r.Context(), "portal.profile.update", "success", updated.Username, updated.WindowsSID, peerIP(r.RemoteAddr), map[string]any{"collaboration_enabled": updated.CollaborationEnabled}); err != nil {
		s.internalError(w, "audit profile update", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "profile": profilePayload(updated)})
}

func profilePayload(user store.User) map[string]any {
	return map[string]any{
		"id": strconv.FormatInt(user.ID, 10), "username": user.Username, "display_name": user.DisplayName,
		"collaboration_enabled": user.CollaborationEnabled, "collaboration_capable": !user.Admin,
	}
}

func (s *Server) restartCurrentUserService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Security origin validation failed"})
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	if session.User.Admin {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Employee service is required"})
		return
	}
	if err := s.instances.Restart(r.Context(), session.User.WindowsSID); err != nil {
		s.logger.Printf("Employee service restart failed username=%s", session.User.Username)
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "User service restart could not be started"})
		return
	}
	if err := s.audit(r.Context(), "portal.service.restart", "accepted", session.User.Username, session.User.WindowsSID, peerIP(r.RemoteAddr), nil); err != nil {
		s.internalError(w, "audit employee service restart", err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"success": true, "reconnect_after_ms": 2000})
}
