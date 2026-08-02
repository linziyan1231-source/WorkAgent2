//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/google/uuid"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/auth"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/fsutil"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/provisionipc"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
)

const (
	provisionPendingRoot = "/var/lib/workagent/provisioning"
	defaultTenantDisk    = uint64(20 * 1024 * 1024 * 1024)
	firstTenantProjectID = uint32(10001)
)

type pendingProvision struct {
	SchemaVersion int    `json:"schema_version"`
	UsernameNorm  string `json:"username_norm"`
	TenantID      string `json:"tenant_id"`
	RuntimeUser   string `json:"runtime_user"`
	ProjectID     uint32 `json:"project_id"`
	Phase         string `json:"phase"`
}

type provisionService struct {
	portalPath  string
	pendingRoot string
	adminBinary string
	mu          sync.Mutex
}

func serveProvisionRequests(arguments []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	portalPath := flags.String("config", "/etc/workagent/portal.json", "Portal configuration")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("usage: workagent-provision serve [--config <path>]")
	}
	if os.Geteuid() != 0 {
		return errors.New("provision service must run as root")
	}
	portal, err := config.LoadPortal(*portalPath)
	if err != nil {
		return err
	}
	account, err := user.Lookup(portal.RuntimeUser)
	if err != nil {
		return err
	}
	portalUID, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || portalUID == 0 {
		return errors.New("Portal runtime UID is invalid")
	}
	listener, err := inheritedProvisionListener()
	if err != nil {
		return err
	}
	defer listener.Close()
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	service := &provisionService{
		portalPath: *portalPath, pendingRoot: provisionPendingRoot,
		adminBinary: filepath.Join(filepath.Dir(executable), "workagent-admin"),
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	server, err := provisionipc.Serve(ctx, listener, uint32(portalUID), service.handle)
	if err != nil {
		return err
	}
	<-ctx.Done()
	return server.Close()
}

func inheritedProvisionListener() (net.Listener, error) {
	pid, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
	if err != nil || pid != os.Getpid() || os.Getenv("LISTEN_FDS") != "1" {
		return nil, errors.New("exactly one systemd socket-activation descriptor is required")
	}
	file := os.NewFile(3, "workagent-provision.socket")
	if file == nil {
		return nil, errors.New("systemd socket descriptor is unavailable")
	}
	defer file.Close()
	return provisionipc.ListenerFromFile(file)
}

func (s *provisionService) handle(ctx context.Context, request provisionipc.Request) provisionipc.Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer auth.Zero(request.PortalPassword)
	if err := s.authorizeActor(ctx, request.Actor); err != nil {
		return failedProvision("NOT_AUTHORIZED", err)
	}
	var userValue store.User
	var err error
	switch request.Command {
	case "add-user":
		userValue, err = s.addUser(ctx, request.Username, request.PortalPassword)
	case "set-enabled":
		userValue, err = s.setEnabled(ctx, request.Username, *request.Enabled)
	default:
		err = errors.New("unsupported provision command")
	}
	if err != nil {
		return failedProvision("PROVISION_FAILED", err)
	}
	return provisionipc.Response{OK: true, User: ipcUser(userValue)}
}

func failedProvision(code string, err error) provisionipc.Response {
	return provisionipc.Response{ErrorCode: code, ErrorMessage: err.Error()}
}

func (s *provisionService) authorizeActor(ctx context.Context, actor string) error {
	portal, err := config.LoadPortal(s.portalPath)
	if err != nil {
		return err
	}
	data, err := store.Open(portal.DatabasePath(), portal.AuditPath())
	if err != nil {
		return err
	}
	defer data.Close()
	actorValue, err := data.UserByUsername(ctx, actor)
	if err != nil || !actorValue.Admin || !actorValue.Enabled {
		return errors.New("enabled Portal administrator is required")
	}
	return nil
}

func (s *provisionService) addUser(ctx context.Context, username string, password []byte) (store.User, error) {
	if err := auth.ValidatePortalUsername(username); err != nil {
		return store.User{}, err
	}
	if err := auth.ValidatePortalPassword(password); err != nil {
		return store.User{}, err
	}
	portal, err := config.LoadPortal(s.portalPath)
	if err != nil {
		return store.User{}, err
	}
	norm := store.NormalizeUsername(username)
	if existing, lookupErr := s.lookupManagedUser(ctx, portal, norm); lookupErr == nil {
		if _, pendingErr := os.Lstat(s.pendingPath(norm)); errors.Is(pendingErr, os.ErrNotExist) {
			return store.User{}, fmt.Errorf("Portal employee %s already exists", existing.Username)
		} else if pendingErr != nil {
			return store.User{}, pendingErr
		}
	} else if !errors.Is(lookupErr, store.ErrNotFound) {
		return store.User{}, lookupErr
	}
	pending, err := s.loadOrAllocatePending(portal, norm)
	if err != nil {
		return store.User{}, err
	}
	tenantPath := filepath.Join(portal.Paths.TenantConfigs, pending.TenantID+".json")
	if pending.Phase == "allocated" {
		arguments := []string{
			"--portal-config", s.portalPath,
			"--tenant-id", pending.TenantID,
			"--runtime-user", pending.RuntimeUser,
			"--project-id", strconv.FormatUint(uint64(pending.ProjectID), 10),
			"--disk-hard-limit-bytes", strconv.FormatUint(defaultTenantDisk, 10),
			"--reconcile",
		}
		if err := provisionTenantTo(arguments, io.Discard); err != nil {
			return store.User{}, fmt.Errorf("provision tenant: %w", err)
		}
		pending.Phase = "tenant"
		if err := s.writePending(pending); err != nil {
			return store.User{}, err
		}
	}
	userValue, lookupErr := s.lookupManagedUser(ctx, portal, norm)
	if pending.Phase == "tenant" {
		switch {
		case lookupErr == nil:
			if !matchesPendingUser(userValue, pending, portal) {
				return store.User{}, errors.New("existing Portal identity conflicts with pending provision")
			}
		case errors.Is(lookupErr, store.ErrNotFound):
			if err := s.runAdminWithPassword(password, "create-user", "--config", s.portalPath, "--tenant-config", tenantPath, "--username", username, "--password-fd", "3"); err != nil {
				return store.User{}, fmt.Errorf("create Portal employee: %w", err)
			}
		default:
			return store.User{}, lookupErr
		}
		pending.Phase = "user"
		if err := s.writePending(pending); err != nil {
			return store.User{}, err
		}
	}
	userValue, err = s.lookupManagedUser(ctx, portal, norm)
	if err != nil {
		return store.User{}, err
	}
	if !matchesPendingUser(userValue, pending, portal) {
		return store.User{}, errors.New("provisioned Portal identity does not match pending tenant")
	}
	if !userValue.Enabled {
		if err := s.runAdmin("set-enabled", "--config", s.portalPath, "--username", username, "--enabled=true"); err != nil {
			return store.User{}, fmt.Errorf("enable Portal employee: %w", err)
		}
		userValue, err = s.lookupManagedUser(ctx, portal, norm)
		if err != nil {
			return store.User{}, err
		}
	}
	if !userValue.Enabled {
		return store.User{}, errors.New("provisioned Portal employee remains disabled")
	}
	if err := s.removePending(norm); err != nil {
		return store.User{}, err
	}
	return userValue, nil
}

func (s *provisionService) setEnabled(ctx context.Context, username string, enabled bool) (store.User, error) {
	if err := auth.ValidatePortalUsername(username); err != nil {
		return store.User{}, err
	}
	portal, err := config.LoadPortal(s.portalPath)
	if err != nil {
		return store.User{}, err
	}
	userValue, err := s.lookupManagedUser(ctx, portal, store.NormalizeUsername(username))
	if err != nil {
		return store.User{}, err
	}
	if userValue.Enabled != enabled {
		if err := s.runAdmin("set-enabled", "--config", s.portalPath, "--username", username, "--enabled="+strconv.FormatBool(enabled)); err != nil {
			return store.User{}, err
		}
	}
	return s.lookupManagedUser(ctx, portal, store.NormalizeUsername(username))
}

func (s *provisionService) lookupManagedUser(ctx context.Context, portal config.Portal, username string) (store.User, error) {
	data, err := store.Open(portal.DatabasePath(), portal.AuditPath())
	if err != nil {
		return store.User{}, err
	}
	defer data.Close()
	value, err := data.UserByUsername(ctx, username)
	if err == nil && value.Admin {
		return store.User{}, errors.New("Portal administrator cannot be managed as an employee")
	}
	return value, err
}

func (s *provisionService) loadOrAllocatePending(portal config.Portal, usernameNorm string) (pendingProvision, error) {
	if err := ensurePrivateDirectory(s.pendingRoot); err != nil {
		return pendingProvision{}, err
	}
	path := s.pendingPath(usernameNorm)
	data, err := os.ReadFile(path)
	if err == nil {
		var pending pendingProvision
		if json.Unmarshal(data, &pending) != nil || pending.SchemaVersion != 1 || pending.UsernameNorm != usernameNorm || pending.Phase != "allocated" && pending.Phase != "tenant" && pending.Phase != "user" {
			return pendingProvision{}, errors.New("invalid pending provision record")
		}
		return pending, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return pendingProvision{}, err
	}
	projectID, err := nextProjectID(portal.Paths.TenantConfigs, s.pendingRoot)
	if err != nil {
		return pendingProvision{}, err
	}
	id := uuid.New()
	pending := pendingProvision{
		SchemaVersion: 1, UsernameNorm: usernameNorm, TenantID: id.String(),
		RuntimeUser: "workagent_" + strings.ReplaceAll(id.String(), "-", "")[:12],
		ProjectID:   projectID, Phase: "allocated",
	}
	if err := s.writePending(pending); err != nil {
		return pendingProvision{}, err
	}
	return pending, nil
}

func (s *provisionService) writePending(pending pendingProvision) error {
	payload, err := json.Marshal(pending)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(s.pendingPath(pending.UsernameNorm), append(payload, '\n'), fsutil.AtomicWriteOptions{Mode: 0o600, CheckParent: true, SafeParent: true})
}

func (s *provisionService) removePending(usernameNorm string) error {
	path := s.pendingPath(usernameNorm)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory, err := os.Open(s.pendingRoot)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (s *provisionService) pendingPath(usernameNorm string) string {
	digest := sha256.Sum256([]byte(usernameNorm))
	return filepath.Join(s.pendingRoot, hex.EncodeToString(digest[:])+".json")
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("provision pending directory is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 {
		return errors.New("provision pending directory must be owned by root")
	}
	return nil
}

func nextProjectID(directory, pendingDirectory string) (uint32, error) {
	used := make(map[uint32]struct{})
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		tenant, err := config.LoadTenant(filepath.Join(directory, entry.Name()))
		if err != nil {
			return 0, err
		}
		used[tenant.Capacity.ProjectID] = struct{}{}
	}
	pendingEntries, err := os.ReadDir(pendingDirectory)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	for _, entry := range pendingEntries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		payload, err := os.ReadFile(filepath.Join(pendingDirectory, entry.Name()))
		if err != nil {
			return 0, err
		}
		var pending pendingProvision
		if err := json.Unmarshal(payload, &pending); err != nil || pending.SchemaVersion != 1 || pending.ProjectID == 0 {
			return 0, errors.New("invalid pending provision record")
		}
		used[pending.ProjectID] = struct{}{}
	}
	for candidate := firstTenantProjectID; candidate != 0; candidate++ {
		if _, exists := used[candidate]; !exists {
			return candidate, nil
		}
	}
	return 0, errors.New("no tenant project ID is available")
}

func matchesPendingUser(value store.User, pending pendingProvision, portal config.Portal) bool {
	return !value.Admin && value.UsernameNorm == pending.UsernameNorm && value.TenantID == pending.TenantID && value.RuntimeUser == pending.RuntimeUser && value.DataRoot == filepath.Join(portal.Paths.TenantData, pending.TenantID)
}

func ipcUser(value store.User) *provisionipc.User {
	return &provisionipc.User{Username: value.Username, TenantID: value.TenantID, RuntimeUser: value.RuntimeUser, Enabled: value.Enabled}
}

func (s *provisionService) runAdmin(arguments ...string) error {
	command := exec.Command(s.adminBinary, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("workagent-admin failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (s *provisionService) runAdminWithPassword(password []byte, arguments ...string) error {
	reader, writer, err := os.Pipe()
	if err != nil {
		return err
	}
	if _, err := writer.Write(password); err != nil {
		reader.Close()
		writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		reader.Close()
		return err
	}
	defer reader.Close()
	command := exec.Command(s.adminBinary, arguments...)
	command.ExtraFiles = []*os.File{reader}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("workagent-admin failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
