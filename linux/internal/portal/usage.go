package portal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/portalusage"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
)

func (s *Server) currentUsage(writer http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "message": "Quota request does not accept query parameters"})
		return
	}
	if s.usage == nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "Quota service is not configured"})
		return
	}
	userValue := request.Context().Value(userContextKey).(store.User)
	ctx, cancel := context.WithTimeout(request.Context(), time.Duration(s.cfg.Usage.QueryTimeoutSeconds)*time.Second)
	defer cancel()
	if err := s.ensureRuntime(ctx, userValue); err != nil {
		s.usageFailure("instance_unavailable", userValue.TenantID)
		s.writeUsageError(writer, ctx, http.StatusServiceUnavailable, "Your AionUi instance is unavailable")
		return
	}
	summary, err := s.usage.Current(ctx, userValue.TenantID)
	if err != nil {
		s.usageFailure("management_query_failed", userValue.TenantID)
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			writeJSON(writer, http.StatusGatewayTimeout, map[string]any{"success": false, "message": "Quota request timed out"})
			return
		}
		writeJSON(writer, http.StatusBadGateway, map[string]any{"success": false, "message": "Quota service is temporarily unavailable"})
		return
	}
	if s.cfg.ChatForward.Enabled {
		quota, err := s.store.ChatGPTProQuota(request.Context(), userValue.ID, s.cfg.ChatForward.WeeklyProLimit, s.now())
		if err != nil {
			s.internalError(writer, "read ChatGPT Pro quota", err)
			return
		}
		for index := range summary.Providers {
			if summary.Providers[index].Kind == "chatgpt" {
				summary.Providers[index].Pro = &portalusage.CountWindow{Used: quota.Confirmed + quota.Pending, Limit: quota.Limit, ResetAt: quota.ResetAt.Format(time.RFC3339)}
				break
			}
		}
	}
	storage, err := s.readStorageUsage(ctx, userValue)
	if err != nil {
		s.usageFailure("storage_unavailable", userValue.TenantID)
	} else {
		summary.Storage = &storage
	}
	snapshot, err := portalusage.MarshalSummarySnapshot(summary)
	if err != nil {
		s.usageFailure("snapshot_encode_failed", userValue.TenantID)
	} else {
		defer clear(snapshot)
		if err := s.writeUsageSnapshot(ctx, userValue, snapshot); err != nil {
			s.usageFailure("snapshot_write_failed", userValue.TenantID)
		}
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, map[string]any{"success": true, "data": summary})
}

func (s *Server) readRuntimeStorageUsage(ctx context.Context, userValue store.User) (portalusage.StorageUsage, error) {
	var usage portalusage.StorageUsage
	if err := s.callRuntimeControl(ctx, userValue, http.MethodGet, "/internal/storage-usage", nil, &usage); err != nil {
		return portalusage.StorageUsage{}, err
	}
	if err := portalusage.ValidateStorageUsage(usage); err != nil {
		return portalusage.StorageUsage{}, errors.New("UserHost returned invalid private storage usage")
	}
	return usage, nil
}

func (s *Server) writeRuntimeUsageSnapshot(ctx context.Context, userValue store.User, snapshot []byte) error {
	if _, err := portalusage.ParseSummarySnapshot(snapshot); err != nil {
		return errors.New("usage snapshot is invalid")
	}
	return s.callRuntimeControl(ctx, userValue, http.MethodPost, "/internal/usage-snapshot", json.RawMessage(snapshot), nil)
}

func (s *Server) usageFailure(stage, tenantID string) {
	s.logger.Printf("Portal quota request failed stage=%s tenant_id=%s", stage, tenantID)
}

func (s *Server) writeUsageError(writer http.ResponseWriter, ctx context.Context, status int, message string) {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		writeJSON(writer, http.StatusGatewayTimeout, map[string]any{"success": false, "message": "Quota request timed out"})
		return
	}
	writeJSON(writer, status, map[string]any{"success": false, "message": message})
}
