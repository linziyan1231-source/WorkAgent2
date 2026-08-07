package portal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"aionuiportal/internal/ipc"
	"aionuiportal/internal/portalusage"
	"aionuiportal/internal/store"
)

func (s *Server) managedUsersUsage(ctx context.Context, users []store.User) ([]map[string]any, error) {
	sids := make([]string, len(users))
	for index, user := range users {
		sids[index] = user.WindowsSID
	}
	summaries, err := s.usage.CurrentMany(ctx, sids)
	if err != nil {
		return nil, err
	}
	for _, user := range users {
		cacheKey := strings.ToUpper(user.WindowsSID)
		summary, ok := summaries[cacheKey]
		if !ok {
			continue
		}
		quota, quotaErr := s.store.ChatGPTProQuota(ctx, user.ID, s.now())
		if quotaErr != nil {
			return nil, quotaErr
		}
		for index := range summary.Providers {
			if summary.Providers[index].Kind == portalusage.KindChatGPT {
				summary.Providers[index].Pro = &portalusage.CountWindow{Used: quota.Confirmed + quota.Pending, Limit: quota.Limit, ResetAt: quota.ResetAt.Format(time.RFC3339)}
				break
			}
		}
		summaries[cacheKey] = summary
	}

	storageBySID := make(map[string]portalusage.StorageUsage)
	var storageMu sync.Mutex
	var storageWait sync.WaitGroup
	storageSlots := make(chan struct{}, 4)
	for _, user := range users {
		if !user.Enabled {
			continue
		}
		if _, available := summaries[strings.ToUpper(user.WindowsSID)]; !available {
			continue
		}
		storageWait.Add(1)
		go func(user store.User) {
			defer storageWait.Done()
			select {
			case storageSlots <- struct{}{}:
				defer func() { <-storageSlots }()
			case <-ctx.Done():
				return
			}
			finish, beginErr := s.instances.BeginRequest(user.WindowsSID, false)
			if beginErr != nil {
				s.logger.Printf("Administrator storage usage unavailable username=%s", user.Username)
				return
			}
			defer finish()
			storage, storageErr := s.instances.StorageUsage(ctx, user.WindowsSID)
			if storageErr != nil {
				s.logger.Printf("Administrator storage usage unavailable username=%s", user.Username)
				return
			}
			storageMu.Lock()
			storageBySID[strings.ToUpper(user.WindowsSID)] = portalStorageUsage(storage)
			storageMu.Unlock()
		}(user)
	}
	storageWait.Wait()

	items := make([]map[string]any, 0, len(users))
	for _, user := range users {
		cacheKey := strings.ToUpper(user.WindowsSID)
		summary, ok := summaries[cacheKey]
		if !ok {
			items = append(items, map[string]any{"username": user.Username, "resource_usage_unavailable": true})
			continue
		}
		if storage, found := storageBySID[cacheKey]; found {
			summary.Storage = &storage
		}
		items = append(items, map[string]any{"username": user.Username, "resource_usage": summary})
	}
	return items, nil
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
		value := portalStorageUsage(storage)
		summary.Storage = &value
	}
	if snapshot, marshalErr := json.Marshal(summary); marshalErr != nil {
		s.usageFailure("snapshot_encode_failed")
	} else if writeErr := s.instances.WriteUsageSnapshot(ctx, session.User.WindowsSID, snapshot); writeErr != nil {
		s.usageFailure("snapshot_write_failed")
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": summary})
}

func portalStorageUsage(storage ipc.StorageUsage) portalusage.StorageUsage {
	return portalusage.StorageUsage{
		Personal: portalusage.StorageBucketUsage{LimitBytes: storage.Personal.LimitBytes, UsedBytes: storage.Personal.UsedBytes, RemainingBytes: storage.Personal.RemainingBytes, MeasuredAt: storage.Personal.MeasuredAt},
		Shared:   portalusage.StorageBucketUsage{LimitBytes: storage.Shared.LimitBytes, UsedBytes: storage.Shared.UsedBytes, RemainingBytes: storage.Shared.RemainingBytes, MeasuredAt: storage.Shared.MeasuredAt},
	}
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
