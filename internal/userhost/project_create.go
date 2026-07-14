package userhost

import (
	"errors"
	"fmt"
	"os"

	"aionuiportal/internal/ipc"
	"aionuiportal/internal/projectfs"
	"aionuiportal/internal/winutil"
)

func (h *Host) createProject(request ipc.ProjectCreateRequest) (ipc.ProjectCreateResult, string, error) {
	if !h.validOAuthInstance(request.InstanceID) {
		return ipc.ProjectCreateResult{}, "PROJECT_CREATE_UNAVAILABLE", errors.New("project creation did not match this healthy UserHost instance")
	}
	return createProjectState(h.dirs.Workspace, h.cfg.WindowsSID, request.Name)
}

func createProjectState(workspaceRoot, sid, name string) (ipc.ProjectCreateResult, string, error) {
	target, ok := projectfs.ResolveChild(workspaceRoot, name)
	if !ok {
		return ipc.ProjectCreateResult{}, "INVALID_PROJECT_NAME", errors.New("project name is invalid")
	}
	policy := winutil.PrivateTreePolicy(sid)
	if err := winutil.VerifyACL(workspaceRoot, policy); err != nil {
		return ipc.ProjectCreateResult{}, "PROJECT_CREATE_FAILED", fmt.Errorf("verify project workspace ACL: %w", err)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ipc.ProjectCreateResult{}, "PROJECT_EXISTS", errors.New("project directory already exists")
		}
		return ipc.ProjectCreateResult{}, "PROJECT_CREATE_FAILED", fmt.Errorf("create project directory: %w", err)
	}
	if err := errors.Join(winutil.ApplyACL(target, policy), winutil.VerifyACL(target, policy)); err != nil {
		return ipc.ProjectCreateResult{}, "PROJECT_CREATE_FAILED", errors.Join(fmt.Errorf("protect project directory: %w", err), os.Remove(target))
	}
	return ipc.ProjectCreateResult{Path: target}, "", nil
}
