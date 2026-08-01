package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aionuiportal/internal/admin"
	"aionuiportal/internal/provisionipc"
	"golang.org/x/sys/windows/svc"
)

const provisionServiceName = "AionUiPortalAdmin"

type provisionServiceHandler struct {
	configPath       string
	scriptsDirectory string
}

func provisionServiceCommand(configPath string, arguments []string) int {
	flags := flag.NewFlagSet("portal service", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	defaultScripts := filepath.Join(filepath.Dir(os.Args[0]), "admin-scripts")
	scriptsDirectory := flags.String("scripts", defaultScripts, "protected administration scripts directory")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: portal --config <path> service [--scripts <path>]")
		return 2
	}
	if err := svc.Run(provisionServiceName, &provisionServiceHandler{configPath: configPath, scriptsDirectory: *scriptsDirectory}); err != nil {
		fmt.Fprintf(os.Stderr, "Portal administration service failed: %v\n", err)
		return 1
	}
	return 0
}

func (h *provisionServiceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveProvisioner(ctx, h.configPath, h.scriptsDirectory) }()
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
				if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
					return false, 1
				}
				return false, 0
			}
		}
	}
}

func serveProvisioner(ctx context.Context, configPath, scriptsDirectory string) error {
	manager, err := admin.Open(configPath)
	if err != nil {
		return err
	}
	defer manager.Close()
	sddl, err := provisionipc.SDDL(manager.Config.PortalServiceSID)
	if err != nil {
		return err
	}
	provisioner := admin.EmployeeProvisioner{Manager: manager, ScriptsDirectory: scriptsDirectory}
	server, err := provisionipc.Listen(ctx, sddl, func(requestCtx context.Context, request provisionipc.Request, report func(provisionipc.Progress)) provisionipc.Response {
		user, err := provisioner.AddWithProgress(requestCtx, request.Username, request.PortalPassword, func(percent int, step string) {
			report(provisionipc.Progress{Percent: percent, Step: step})
		})
		if err != nil {
			return provisionipc.Response{ErrorCode: provisionErrorCode(err), ErrorMessage: err.Error()}
		}
		return provisionipc.Response{OK: true, User: &provisionipc.User{Username: user.Username, WindowsUsername: user.WindowsUsername, WindowsSID: user.WindowsSID}}
	})
	if err != nil {
		return err
	}
	defer server.Close()
	<-ctx.Done()
	return ctx.Err()
}

func provisionErrorCode(err error) string {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "portal username already exists"):
		return "PORTAL_USERNAME_EXISTS"
	case strings.Contains(message, "unmanaged windows account already uses this username"), strings.Contains(message, "windows error 2224"):
		return "WINDOWS_USERNAME_EXISTS"
	case strings.Contains(message, "already mapped to portal user"):
		return "WINDOWS_ACCOUNT_MAPPED"
	case strings.Contains(message, "does not match the windows account"), strings.Contains(message, "existing portal account is not an enabled employee account"):
		return "ACCOUNT_CONFLICT"
	default:
		return "PROVISION_FAILED"
	}
}
