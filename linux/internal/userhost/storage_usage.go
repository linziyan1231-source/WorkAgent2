package userhost

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/hostcheck"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/portalusage"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/storageusage"
)

const (
	defaultUserStorageLimitBytes = uint64(20 * 1024 * 1024 * 1024)
	usageSnapshotPath            = "data/quota-summary.json"
)

type quotaVerifier func(string, uint32, uint64) (hostcheck.ProjectQuotaStatus, error)
type treeMeasurer func(context.Context, string) (uint64, error)

func (h *Host) storageUsageHandler(writer http.ResponseWriter, request *http.Request) {
	usage, usedQuota, err := measureStorageUsageWith(request.Context(), h.cfg.DataRoot, h.cfg.Capacity, hostcheck.VerifyTenantQuota, storageusage.MeasureTree, time.Now)
	if err != nil {
		h.logger.Printf("tenant private storage usage failed stage=measurement tenant_id=%s", h.cfg.TenantID)
		writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"success": false, "code": "STORAGE_USAGE_UNAVAILABLE"})
		return
	}
	if h.cfg.Capacity.ProjectID != 0 && !usedQuota {
		h.logger.Printf("tenant private storage usage used secure tree fallback tenant_id=%s", h.cfg.TenantID)
	}
	writeJSON(writer, http.StatusOK, usage)
}

func (h *Host) usageSnapshotHandler(writer http.ResponseWriter, request *http.Request) {
	payload, err := io.ReadAll(io.LimitReader(request.Body, portalusage.MaxSummarySnapshotBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > portalusage.MaxSummarySnapshotBytes {
		clear(payload)
		h.logger.Printf("tenant usage snapshot failed stage=invalid_payload tenant_id=%s", h.cfg.TenantID)
		writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "code": "INVALID_USAGE_SNAPSHOT"})
		return
	}
	defer clear(payload)
	summary, err := portalusage.ParseSummarySnapshot(payload)
	if err != nil {
		h.logger.Printf("tenant usage snapshot failed stage=invalid_summary tenant_id=%s", h.cfg.TenantID)
		writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "code": "INVALID_USAGE_SNAPSHOT"})
		return
	}
	canonical, err := portalusage.MarshalSummarySnapshot(summary)
	if err != nil {
		h.logger.Printf("tenant usage snapshot failed stage=invalid_summary tenant_id=%s", h.cfg.TenantID)
		writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "code": "INVALID_USAGE_SNAPSHOT"})
		return
	}
	defer clear(canonical)
	if err := request.Context().Err(); err != nil || h.dataRoot == nil {
		h.logger.Printf("tenant usage snapshot failed stage=runtime_unavailable tenant_id=%s", h.cfg.TenantID)
		writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"success": false, "code": "USAGE_SNAPSHOT_WRITE_FAILED"})
		return
	}
	if err := h.dataRoot.WriteFileAtomic(usageSnapshotPath, canonical, 0o600); err != nil {
		h.logger.Printf("tenant usage snapshot failed stage=private_write tenant_id=%s", h.cfg.TenantID)
		writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"success": false, "code": "USAGE_SNAPSHOT_WRITE_FAILED"})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"success": true})
}

func measureStorageUsage(ctx context.Context, root string, capacity config.TenantCapacity) (portalusage.StorageUsage, error) {
	usage, _, err := measureStorageUsageWith(ctx, root, capacity, hostcheck.VerifyTenantQuota, storageusage.MeasureTree, time.Now)
	return usage, err
}

func measureStorageUsageWith(ctx context.Context, root string, capacity config.TenantCapacity, verify quotaVerifier, measure treeMeasurer, now func() time.Time) (portalusage.StorageUsage, bool, error) {
	if err := ctx.Err(); err != nil {
		return portalusage.StorageUsage{}, false, err
	}
	if (capacity.ProjectID == 0) != (capacity.DiskHardLimitBytes == 0) {
		return portalusage.StorageUsage{}, false, errors.New("private storage quota configuration is inconsistent")
	}
	if verify == nil || measure == nil || now == nil {
		return portalusage.StorageUsage{}, false, errors.New("private storage measurement dependency is unavailable")
	}
	limit := capacity.DiskHardLimitBytes
	if limit == 0 {
		limit = defaultUserStorageLimitBytes
	}
	if capacity.ProjectID != 0 {
		status, err := verify(root, capacity.ProjectID, capacity.DiskHardLimitBytes)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return portalusage.StorageUsage{}, false, ctxErr
		}
		if err == nil && status.ProjectID == capacity.ProjectID && status.HardLimitBytes == capacity.DiskHardLimitBytes && status.Inherit && status.UsedBytes <= status.HardLimitBytes {
			return newStorageUsage(limit, status.UsedBytes, now()), true, nil
		}
	}
	used, err := measure(ctx, root)
	if err != nil {
		return portalusage.StorageUsage{}, false, err
	}
	if err := ctx.Err(); err != nil {
		return portalusage.StorageUsage{}, false, err
	}
	return newStorageUsage(limit, used, now()), false, nil
}

func newStorageUsage(limit, used uint64, measuredAt time.Time) portalusage.StorageUsage {
	remaining := uint64(0)
	if used < limit {
		remaining = limit - used
	}
	return portalusage.StorageUsage{LimitBytes: limit, UsedBytes: used, RemainingBytes: remaining, MeasuredAt: measuredAt.UTC().Format(time.RFC3339)}
}
