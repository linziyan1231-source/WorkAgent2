package portal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"aionuiportal/internal/portalusage"
	"aionuiportal/internal/store"
)

func (s *Server) managedUserUsage(ctx context.Context, user store.User) (portalusage.Summary, error) {
	finish, err := s.instances.BeginRequest(user.WindowsSID, false)
	if err != nil {
		return portalusage.Summary{}, err
	}
	defer finish()
	status, err := s.instances.Status(ctx, user.WindowsSID)
	if err != nil || !status.Healthy {
		if err != nil {
			return portalusage.Summary{}, err
		}
		return portalusage.Summary{}, errors.New("UserHost is not running")
	}
	if !strings.EqualFold(status.WindowsSID, user.WindowsSID) {
		return portalusage.Summary{}, errors.New("UserHost returned an invalid status identity")
	}
	ids, err := s.instances.ModelKeyIDs(ctx, user.WindowsSID)
	if err != nil {
		return portalusage.Summary{}, err
	}
	summary, err := s.usage.Current(ctx, user.WindowsSID, ids)
	if err != nil {
		return portalusage.Summary{}, err
	}
	quota, err := s.store.ChatGPTProQuota(ctx, user.ID, s.now())
	if err != nil {
		return portalusage.Summary{}, err
	}
	for index := range summary.Providers {
		if summary.Providers[index].Kind == portalusage.KindChatGPT {
			summary.Providers[index].Pro = &portalusage.CountWindow{Used: quota.Confirmed + quota.Pending, Limit: quota.Limit, ResetAt: quota.ResetAt.Format(time.RFC3339)}
			break
		}
	}
	storage, err := s.instances.StorageUsage(ctx, user.WindowsSID)
	if err != nil {
		return portalusage.Summary{}, err
	}
	summary.Storage = &portalusage.StorageUsage{LimitBytes: storage.LimitBytes, UsedBytes: storage.UsedBytes, RemainingBytes: storage.RemainingBytes, MeasuredAt: storage.MeasuredAt}
	return summary, nil
}

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
	storage, err := s.instances.StorageUsage(ctx, session.User.WindowsSID)
	if err != nil {
		s.usageFailure("storage_unavailable")
	} else {
		summary.Storage = &portalusage.StorageUsage{
			LimitBytes: storage.LimitBytes, UsedBytes: storage.UsedBytes, RemainingBytes: storage.RemainingBytes, MeasuredAt: storage.MeasuredAt,
		}
	}
	if snapshot, marshalErr := json.Marshal(summary); marshalErr != nil {
		s.usageFailure("snapshot_encode_failed")
	} else if writeErr := s.instances.WriteUsageSnapshot(ctx, session.User.WindowsSID, snapshot); writeErr != nil {
		s.usageFailure("snapshot_write_failed")
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
