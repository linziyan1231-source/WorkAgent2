package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"aionuiportal/internal/kimidatasource"
	"golang.org/x/sys/windows/svc"
)

const serviceName = "AionKimiDatasourceBroker"

type serviceHandler struct{ configPath string }

func main() {
	configPath := flag.String("config", "", "absolute Kimi datasource broker config path")
	serviceMode := flag.Bool("service", false, "run as a Windows service")
	flag.Parse()
	if *configPath == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: AionKimiDatasourceBroker.exe --config <absolute-path>")
		os.Exit(2)
	}
	if *serviceMode {
		if err := svc.Run(serviceName, &serviceHandler{configPath: *configPath}); err != nil {
			fmt.Fprintf(os.Stderr, "FAILED: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := run(context.Background(), *configPath); err != nil {
		fmt.Fprintf(os.Stderr, "FAILED: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, configPath string) error {
	cfg, err := kimidatasource.LoadConfig(configPath)
	if err != nil {
		return err
	}
	server, err := kimidatasource.NewServer(cfg)
	if err != nil {
		return err
	}
	defer server.Close()
	httpServer := &http.Server{Addr: cfg.ListenAddress, Handler: server.Handler(), ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 * 1024}
	done := make(chan error, 1)
	go func() { done <- httpServer.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return err
		}
		err := <-done
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (h *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, h.configPath) }()
	status <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case err := <-done:
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
				if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
					return false, 1
				}
				return false, 0
			}
		}
	}
}
