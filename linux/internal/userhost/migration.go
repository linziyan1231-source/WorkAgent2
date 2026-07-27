package userhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"syscall"
	"time"
)

func (h *Host) runMigration(ctx context.Context) error {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("reserve migration address: %w", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return err
	}
	arguments := make([]string, len(h.cfg.Backend.Migration.Arguments))
	for index, argument := range h.cfg.Backend.Migration.Arguments {
		arguments[index] = expandArgument(argument, address, h.cfg.DataRoot, h.releaseRoot)
	}
	command := exec.CommandContext(ctx, h.cfg.Backend.Migration.Executable, arguments...)
	command.Dir = h.cfg.Backend.Migration.WorkingDirectory
	command.Env = h.runtimeEnvironment(address, true)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	logFile, err := openBoundedLog(h.dataRoot, "logs/migration.log")
	if err != nil {
		return err
	}
	command.Stdout, command.Stderr = logFile, logFile
	if err := startRuntimeCommand(command, h.runtimeToken); err != nil {
		logFile.Close()
		return fmt.Errorf("start backend migration: %w", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- command.Wait()
		_ = logFile.Close()
	}()
	stop := func() {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		timer := time.NewTimer(time.Duration(h.cfg.Backend.Migration.ShutdownTimeoutSeconds) * time.Second)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			<-done
		}
	}
	if err := verifyBackendExecutable(command.Process.Pid, h.cfg.Backend.Migration.Executable); err != nil {
		stop()
		return fmt.Errorf("verify migration executable: %w", err)
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 1500 * time.Millisecond, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	deadline := time.Now().Add(time.Duration(h.cfg.Backend.Migration.StartupTimeoutSeconds) * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			if err == nil {
				return errors.New("migration process exited before its health endpoint became ready")
			}
			return fmt.Errorf("migration process exited before readiness: %w", err)
		case <-ctx.Done():
			stop()
			return ctx.Err()
		default:
		}
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+h.cfg.Backend.Migration.HealthPath, nil)
		setWorkAgentRuntimeHeader(request, h.runtimeToken)
		response, requestErr := client.Do(request)
		if requestErr == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				if err := verifyBackendProcess(address, command.Process.Pid, h.cfg.Backend.Migration.Executable); err != nil {
					stop()
					return fmt.Errorf("verify migration listener ownership: %w", err)
				}
				stop()
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	stop()
	return errors.New("backend migration did not become healthy before its deadline")
}
