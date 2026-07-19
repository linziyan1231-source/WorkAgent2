package portal

import (
	"context"
	"errors"
	"net/http"
	"time"

	"aionuiportal/internal/portalusage"
)

func (s *Server) currentUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	if r.URL.RawQuery != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Quota request does not accept query parameters"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.UsageQueryTimeoutSecs)*time.Second)
	defer cancel()
	finish, err := s.instances.BeginRequest(session.User.WindowsSID, false)
	if err != nil {
		s.usageFailure("instance_draining")
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "Your AionUi instance is draining"})
		return
	}
	defer finish()
	if _, err := s.instances.Ensure(ctx, session.User.WindowsSID); err != nil {
		s.usageFailure("instance_unavailable")
		s.writeUsageContextError(w, ctx, "Your AionUi instance is unavailable")
		return
	}
	ids, err := s.instances.ModelKeyIDs(ctx, session.User.WindowsSID)
	if err != nil {
		s.usageFailure("mapping_unavailable")
		s.writeUsageContextError(w, ctx, "Quota mapping is unavailable")
		return
	}
	summary, err := s.usage.Current(ctx, session.User.WindowsSID, ids)
	if err != nil {
		s.usageFailure(portalusage.RemoteFailureStage(err))
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			writeJSON(w, http.StatusGatewayTimeout, map[string]any{"success": false, "message": "Quota request timed out"})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]any{"success": false, "message": "Quota service is temporarily unavailable"})
		return
	}
	quota, err := s.store.ChatGPTProQuota(r.Context(), session.User.ID, s.now())
	if err != nil {
		s.internalError(w, "read ChatGPT Pro quota", err)
		return
	}
	for index := range summary.Providers {
		if summary.Providers[index].Kind == portalusage.KindChatGPT {
			summary.Providers[index].Pro = &portalusage.CountWindow{
				Used:    quota.Confirmed + quota.Pending,
				Limit:   quota.Limit,
				ResetAt: quota.ResetAt.Format(time.RFC3339),
			}
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": summary})
}

func (s *Server) writeUsageContextError(w http.ResponseWriter, ctx context.Context, message string) {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		writeJSON(w, http.StatusGatewayTimeout, map[string]any{"success": false, "message": "Quota request timed out"})
		return
	}
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": message})
}

func (s *Server) usageFailure(stage string) {
	s.logger.Printf("Portal quota request failed stage=%s", stage)
}
