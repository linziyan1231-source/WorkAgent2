package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/admin"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/portal"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/safelog"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/sdnotify"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "", "absolute Portal configuration path")
	flag.Parse()
	logger := log.New(safelog.NewWriter(os.Stderr, "workagent-portal"), "", 0)
	if os.Geteuid() == 0 {
		logger.Fatal("Portal must run as a dedicated non-root account")
	}
	if configPath == "" {
		logger.Fatal("--config is required")
	}
	cfg, err := config.LoadPortal(configPath)
	if err != nil {
		logger.Fatal(err)
	}
	if err := cfg.ValidateProductionLayout(configPath); err != nil {
		logger.Fatal(err)
	}
	if err := admin.VerifyPortalFiles(cfg, configPath); err != nil {
		logger.Fatal(err)
	}
	serviceContext, cancelServiceCheck := context.WithTimeout(context.Background(), 10*time.Second)
	serviceErr := admin.VerifyPortalService(serviceContext, cfg, nil)
	cancelServiceCheck()
	if serviceErr != nil {
		logger.Fatal(serviceErr)
	}
	account, err := user.Lookup(cfg.RuntimeUser)
	if err != nil {
		logger.Fatalf("lookup Portal runtime account: %v", err)
	}
	expectedUID, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || expectedUID == 0 || uint64(os.Geteuid()) != expectedUID {
		logger.Fatal("Portal process UID does not match its configured dedicated account")
	}
	brand, err := productconfig.LoadBrand(cfg.BrandFile)
	if err != nil {
		logger.Fatal(err)
	}
	policy, err := productconfig.LoadPolicy(cfg.PolicyFile)
	if err != nil {
		logger.Fatal(err)
	}
	data, err := store.Open(cfg.DatabasePath(), cfg.AuditPath())
	if err != nil {
		logger.Fatal(err)
	}
	defer data.Close()
	application, err := portal.New(cfg, data, brand, policy, logger)
	if err != nil {
		logger.Fatal(err)
	}
	listener, cleanup, err := listen(cfg.Listener)
	if err != nil {
		logger.Fatal(err)
	}
	defer cleanup()
	server := &http.Server{
		Handler:           application.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 * 1024,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	serverError := make(chan error, 1)
	go func() {
		if cfg.Listener.TLSCertificateFile != "" {
			serverError <- server.ServeTLS(listener, cfg.Listener.TLSCertificateFile, cfg.Listener.TLSPrivateKeyFile)
			return
		}
		serverError <- server.Serve(listener)
	}()
	_ = sdnotify.Notify("READY=1\nSTATUS=WorkAgent2 Portal is ready")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go sdnotify.Watchdog(ctx)
	go auditRetentionLoop(ctx, data, cfg, logger)
	select {
	case <-ctx.Done():
		_ = sdnotify.Notify("STOPPING=1\nSTATUS=WorkAgent2 Portal is stopping")
		shutdownContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			logger.Printf("graceful shutdown failed: %v", err)
			_ = server.Close()
		}
	case err := <-serverError:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal(err)
		}
	}
}

func auditRetentionLoop(ctx context.Context, data *store.Store, cfg config.Portal, logger *log.Logger) {
	run := func() {
		operationContext, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		before := time.Now().UTC().Add(-time.Duration(cfg.Observability.AuditRetentionDays) * 24 * time.Hour)
		deleted, err := data.PruneAudit(operationContext, before, cfg.Observability.AuditMinimumEvents)
		if err != nil {
			logger.Printf("audit retention failed: %v", err)
			return
		}
		if deleted > 0 {
			logger.Printf("audit retention completed deleted=%d", deleted)
		}
	}
	run()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func listen(cfg config.Listener) (net.Listener, func(), error) {
	if cfg.Network == "tcp" {
		listener, err := net.Listen("tcp", cfg.Address)
		return listener, func() {
			if listener != nil {
				_ = listener.Close()
			}
		}, err
	}
	parent := filepath.Dir(cfg.Address)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, func() {}, err
	}
	if info, err := os.Lstat(cfg.Address); err == nil {
		if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
			return nil, func() {}, fmt.Errorf("refusing to replace non-socket listener path")
		}
		if err := os.Remove(cfg.Address); err != nil {
			return nil, func() {}, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, func() {}, err
	}
	listener, err := net.Listen("unix", cfg.Address)
	if err != nil {
		return nil, func() {}, err
	}
	if err := os.Chmod(cfg.Address, 0o600); err != nil {
		listener.Close()
		return nil, func() {}, err
	}
	return listener, func() {
		_ = listener.Close()
		_ = os.Remove(cfg.Address)
	}, nil
}
