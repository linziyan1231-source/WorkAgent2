package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"aionuiportal/internal/adminipc"
	"aionuiportal/internal/cliproxy"
	"aionuiportal/internal/config"
	"aionuiportal/internal/instance"
	"aionuiportal/internal/ipc"
	"aionuiportal/internal/portal"
	"aionuiportal/internal/portalusage"
	"aionuiportal/internal/release"
	"aionuiportal/internal/scheduler"
	"aionuiportal/internal/store"
	"golang.org/x/sys/windows/svc"
)

const serviceName = "AionUiPortal"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 || (args[0] != "service" && args[0] != "console") {
		fmt.Fprintln(os.Stderr, "usage: AionUiPortal.exe <service|console> --config <absolute-path>")
		return 2
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "", "absolute Portal configuration path")
	if err := flags.Parse(args[1:]); err != nil || *configPath == "" || flags.NArg() != 0 {
		return 2
	}
	if args[0] == "service" {
		if err := svc.Run(serviceName, &serviceHandler{configPath: *configPath}); err != nil {
			fmt.Fprintf(os.Stderr, "Portal Windows Service failed: %v\n", err)
			return 1
		}
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runPortal(ctx, *configPath); err != nil {
		fmt.Fprintf(os.Stderr, "Portal stopped with an error: %v\n", err)
		return 1
	}
	return 0
}

type serviceHandler struct {
	configPath string
}

func (h *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runPortal(ctx, h.configPath) }()
	status <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case err := <-done:
			status <- svc.Status{State: svc.StopPending}
			if err != nil {
				return false, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				err := <-done
				if err != nil {
					return false, 1
				}
				return false, 0
			}
		}
	}
}

func runPortal(ctx context.Context, configPath string) error {
	cfg, err := config.LoadPortal(configPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.PortalLogPath), 0o700); err != nil {
		return fmt.Errorf("create Portal log directory: %w", err)
	}
	logFile, err := os.OpenFile(cfg.PortalLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open Portal log: %w", err)
	}
	defer logFile.Close()
	logger := log.New(logFile, "", log.Ldate|log.Ltime|log.LUTC)
	verified, err := release.VerifyCurrent(cfg.CurrentReleaseFile, cfg.ReleasesRoot, cfg.SupportedAionCore)
	if err != nil {
		logger.Printf("Portal startup failed release verification: %v", err)
		return err
	}
	data, err := store.Open(cfg.DatabasePath, cfg.AuditLogPath)
	if err != nil {
		logger.Printf("Portal startup failed database initialization: %v", err)
		return err
	}
	defer data.Close()
	manager := instance.New(cfg, data, scheduler.Controller{})
	usageRemote, err := portalusage.NewManagementRemote(cliproxy.ManagementOptions{BaseURL: cfg.UsageManagementURL, KeyFile: cfg.UsageManagementKeyFile})
	if err != nil {
		return fmt.Errorf("initialize Portal quota Management API client: %w", err)
	}
	usage, err := portalusage.NewService(usageRemote, time.Duration(cfg.UsageCacheSeconds)*time.Second, time.Now)
	if err != nil {
		return fmt.Errorf("initialize Portal quota service: %w", err)
	}
	adminSDDL, err := adminipc.SDDL(cfg.PortalServiceSID)
	if err != nil {
		return err
	}
	adminPipe, err := adminipc.Listen(ctx, adminSDDL, func(requestCtx context.Context, request adminipc.Request) adminipc.Response {
		if request.Command != "status" {
			return adminipc.Response{OK: false, ErrorCode: "UNKNOWN_COMMAND", ErrorMessage: "unsupported admin command"}
		}
		user, err := data.UserBySID(requestCtx, request.WindowsSID)
		if err != nil {
			return adminipc.Response{OK: false, ErrorCode: "USER_NOT_FOUND", ErrorMessage: "Portal user mapping does not exist"}
		}
		status, statusErr := manager.Status(requestCtx, request.WindowsSID)
		if statusErr != nil {
			status = ipc.Status{WindowsSID: request.WindowsSID, State: "stopped", Healthy: false, FailureReason: "UserHost IPC is unavailable"}
		}
		sessions, err := data.SessionCountForUser(requestCtx, user.ID, time.Now())
		if err != nil {
			return adminipc.Response{OK: false, ErrorCode: "STORE_FAILED", ErrorMessage: "Portal session count is unavailable"}
		}
		requests, webSockets := manager.ConnectionCounts(request.WindowsSID)
		return adminipc.Response{OK: true, Status: &status, Sessions: sessions, Requests: requests, WebSockets: webSockets}
	})
	if err != nil {
		return fmt.Errorf("start protected Portal admin IPC: %w", err)
	}
	defer adminPipe.Close()
	server, err := portal.New(cfg, data, manager, usage, filepath.Join(verified.Path, "static"), logger)
	if err != nil {
		return err
	}
	reaperCtx, stopReaper := context.WithCancel(ctx)
	defer stopReaper()
	go reapLoop(reaperCtx, manager, logger)
	logger.Printf("Portal starting listen=%s public_base_url=%s release=%s", cfg.ListenAddress, cfg.PublicBaseURL, verified.Manifest.Version)
	err = server.Run(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Printf("Portal server stopped with error: %v", err)
		return err
	}
	logger.Print("Portal stopped")
	return nil
}

func reapLoop(ctx context.Context, manager *instance.Manager, logger *log.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			failures := manager.ReapOnce(probeCtx)
			cancel()
			for _, failure := range failures {
				logger.Printf("idle-reap probe failed safely: %v", failure)
			}
		}
	}
}
