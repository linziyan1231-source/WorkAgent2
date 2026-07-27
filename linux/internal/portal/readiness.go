package portal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/admin"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/cliproxy"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/hostcheck"
)

type readinessComponent struct {
	Ready bool `json:"ready"`
}

type readinessReport struct {
	Status     string                        `json:"status"`
	Ready      bool                          `json:"ready"`
	CheckedAt  time.Time                     `json:"checked_at"`
	PolicyID   string                        `json:"policy_id"`
	BrandID    string                        `json:"brand_id"`
	Components map[string]readinessComponent `json:"components"`
}

func (s *Server) checkReadiness(ctx context.Context) readinessReport {
	report := readinessReport{Status: "ready", Ready: true, CheckedAt: s.now(), PolicyID: s.policy.PolicyID, BrandID: s.brand.BrandID, Components: make(map[string]readinessComponent)}
	check := func(name string, operation func() error) {
		err := operation()
		report.Components[name] = readinessComponent{Ready: err == nil}
		if err != nil {
			report.Ready = false
			report.Status = "not_ready"
			s.logger.Printf("readiness component %s failed: %v", name, err)
		}
	}
	check("database", func() error { return s.store.Ping(ctx) })
	check("audit", s.store.CheckAuditSink)
	check("brand", s.brand.Validate)
	check("renderer", func() error {
		if s.rendererRoot == "" {
			return errors.New("signed production Renderer release is not configured")
		}
		info, err := os.Lstat(filepath.Join(s.rendererRoot, "index.html"))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 8*1024*1024 {
			return errors.New("production Renderer index is missing or unsafe")
		}
		return nil
	})
	check("policy", func() error {
		if err := s.policy.Validate(); err != nil {
			return err
		}
		enabled := 0
		for _, model := range s.policy.Models {
			if model.Enabled {
				enabled++
				if _, ok := s.policy.Pricing[model.ID]; !ok {
					return fmt.Errorf("model %s has no pricing", model.ID)
				}
				if _, ok := s.policy.Quotas[model.ID]; !ok {
					return fmt.Errorf("model %s has no quota", model.ID)
				}
			}
		}
		if s.policy.ApprovalRequired {
			return errors.New("model policy is awaiting approval")
		}
		if enabled == 0 {
			return errors.New("model policy enables no models")
		}
		return nil
	})
	check("host", func() error {
		value, err := hostcheck.Inspect(s.cfg)
		if err != nil {
			return err
		}
		return value.Error()
	})
	check("tenants", func() error { return s.checkTenantReadiness(ctx) })
	check("cli_proxy", func() error {
		checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return cliproxy.CheckReadiness(checkCtx, s.cfg.CLIProxy, s.policy)
	})
	if s.cfg.ChatForward.Enabled {
		check("chat_forward", func() error { return s.checkChatForward(ctx) })
	}
	if s.cfg.Notifications.Enabled {
		check("notifications", func() error {
			if s.notifications == nil {
				return errors.New("notification source is unavailable")
			}
			checkCtx, cancel := context.WithTimeout(ctx, 7*time.Second)
			defer cancel()
			_, err := s.notifications.Fetch(checkCtx)
			return err
		})
	}
	return report
}

func (s *Server) checkTenantReadiness(ctx context.Context) error {
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return err
	}
	enabled := 0
	projectIDs := make(map[uint32]string)
	for _, userValue := range users {
		if !userValue.Enabled {
			continue
		}
		enabled++
		path := filepath.Join(s.cfg.Paths.TenantConfigs, userValue.TenantID+".json")
		tenant, err := config.LoadTenant(path)
		if err != nil {
			return fmt.Errorf("tenant %s configuration: %w", userValue.TenantID, err)
		}
		if tenant.RuntimeUser != userValue.RuntimeUser || tenant.DataRoot != userValue.DataRoot {
			return fmt.Errorf("tenant %s identity is inconsistent", userValue.TenantID)
		}
		if s.cfg.Runtime.RequireProjectQuota {
			if other := projectIDs[tenant.Capacity.ProjectID]; tenant.Capacity.ProjectID == 0 || other != "" {
				return fmt.Errorf("tenant %s has a missing or duplicate XFS project ID", userValue.TenantID)
			}
			projectIDs[tenant.Capacity.ProjectID] = userValue.TenantID
		}
		if err := admin.VerifyTenantConfigPath(s.cfg, tenant, path); err != nil {
			return fmt.Errorf("tenant %s configuration protection: %w", userValue.TenantID, err)
		}
		if _, err := admin.VerifyTenantHost(s.cfg, tenant); err != nil {
			return fmt.Errorf("tenant %s host verification: %w", userValue.TenantID, err)
		}
		if err := admin.VerifyTenantService(ctx, s.cfg, tenant, admin.ServiceVerificationOptions{RequireReadySocket: true}); err != nil {
			return fmt.Errorf("tenant %s service verification: %w", userValue.TenantID, err)
		}
	}
	if enabled == 0 {
		return errors.New("no enabled tenants")
	}
	return nil
}

func checkOptionalService(service config.OptionalService) error {
	if !service.Enabled || strings.TrimSpace(service.Endpoint) == "" {
		return errors.New("service is not configured")
	}
	credential, err := readProtectedCredential(service.CredentialFile)
	clear(credential)
	return err
}

func readProtectedCredential(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 16 || info.Size() > 4096 {
		return nil, errors.New("credential file is missing or unsafe")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("credential file is unreadable")
	}
	payload = []byte(strings.TrimSpace(string(payload)))
	if len(payload) < 16 || len(payload) > 4096 || strings.ContainsAny(string(payload), "\x00\r\n") {
		clear(payload)
		return nil, errors.New("credential value is invalid")
	}
	return payload, nil
}
