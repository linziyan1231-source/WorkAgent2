package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/admin"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/ipc"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/safelog"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/userhost"
)

func main() {
	var configPath string
	var tenantID string
	flag.StringVar(&configPath, "config", "", "absolute tenant configuration path")
	flag.StringVar(&tenantID, "tenant-id", "", "tenant UUID expected by this service instance")
	flag.Parse()
	logger := log.New(safelog.NewWriter(os.Stderr, "workagent-userhost"), "", 0)
	if configPath == "" || tenantID == "" {
		logger.Fatal("--config and --tenant-id are required")
	}
	cfg, err := config.LoadTenant(configPath)
	if err != nil {
		logger.Fatal(err)
	}
	if cfg.TenantID != tenantID {
		logger.Fatal("tenant ID does not match the service instance")
	}
	if err := admin.VerifyRuntimeTenantConfigPath(cfg, configPath); err != nil {
		logger.Fatal(err)
	}
	if os.Getenv("LISTEN_FDS") == "" {
		logger.Fatal("systemd socket activation is required")
	}
	listener, err := ipc.ListenerFromSystemd(cfg.PortalUID, cfg.SocketPath)
	if err != nil {
		logger.Fatal(err)
	}
	defer listener.Close()
	host, err := userhost.New(cfg, listener, logger)
	if err != nil {
		logger.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := host.Run(ctx); err != nil {
		logger.Fatal(err)
	}
}
