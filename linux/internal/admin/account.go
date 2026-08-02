package admin

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

type RuntimeAccountVerificationOptions struct {
	RequireSlotGroup      bool
	RequirePasswordLocked bool
}

type RuntimeAccountVerification struct {
	UID uint32
	GID uint32
}

// VerifyRuntimeAccount verifies the durable operating-system identity that a
// tenant service is allowed to use. Password-lock verification is optional so
// the unprivileged Portal can still perform the remainder of the checks.
func VerifyRuntimeAccount(tenant config.Tenant, options RuntimeAccountVerificationOptions) (RuntimeAccountVerification, error) {
	account, err := user.Lookup(tenant.RuntimeUser)
	if err != nil {
		return RuntimeAccountVerification{}, fmt.Errorf("lookup tenant runtime account: %w", err)
	}
	primaryGroup, err := user.LookupGroupId(account.Gid)
	if err != nil {
		return RuntimeAccountVerification{}, fmt.Errorf("lookup tenant primary group: %w", err)
	}
	slotGID := ""
	var groupIDs []string
	if options.RequireSlotGroup {
		slotGroup, err := user.LookupGroup("workagent-slots")
		if err != nil {
			return RuntimeAccountVerification{}, fmt.Errorf("lookup capacity group: %w", err)
		}
		slotGID = slotGroup.Gid
		groupIDs, err = account.GroupIds()
		if err != nil {
			return RuntimeAccountVerification{}, fmt.Errorf("lookup tenant supplementary groups: %w", err)
		}
	}
	passwd, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return RuntimeAccountVerification{}, fmt.Errorf("read account database: %w", err)
	}
	var shadow []byte
	if options.RequirePasswordLocked {
		shadow, err = os.ReadFile("/etc/shadow")
		if err != nil {
			return RuntimeAccountVerification{}, fmt.Errorf("read password-lock database: %w", err)
		}
	}
	return verifyRuntimeAccountEvidence(tenant, account, primaryGroup.Name, slotGID, groupIDs, passwd, shadow, options)
}

func verifyRuntimeAccountEvidence(tenant config.Tenant, account *user.User, primaryGroupName, slotGID string, groupIDs []string, passwd, shadow []byte, options RuntimeAccountVerificationOptions) (RuntimeAccountVerification, error) {
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 || account.Username != tenant.RuntimeUser || account.HomeDir != tenant.DataRoot {
		return RuntimeAccountVerification{}, errors.New("tenant runtime account identity or home directory is invalid")
	}
	if primaryGroupName != tenant.RuntimeUser {
		return RuntimeAccountVerification{}, errors.New("tenant runtime account must use a dedicated same-name primary group")
	}
	passwdFound := false
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 || fields[0] != tenant.RuntimeUser {
			continue
		}
		passwdFound = fields[2] == account.Uid && fields[3] == account.Gid && fields[5] == tenant.DataRoot && (fields[6] == "/usr/sbin/nologin" || fields[6] == "/sbin/nologin")
		break
	}
	if !passwdFound {
		return RuntimeAccountVerification{}, errors.New("tenant runtime account must use its private home and nologin shell")
	}
	if options.RequireSlotGroup {
		if slotGID == "" || slotGID == account.Gid {
			return RuntimeAccountVerification{}, errors.New("capacity group must be a distinct supplementary group")
		}
		allowed := map[string]bool{account.Gid: true, slotGID: true}
		foundPrimary, foundSlot := false, false
		for _, groupID := range groupIDs {
			if !allowed[groupID] {
				return RuntimeAccountVerification{}, fmt.Errorf("tenant runtime account has unexpected supplementary group %s", groupID)
			}
			foundPrimary = foundPrimary || groupID == account.Gid
			foundSlot = foundSlot || groupID == slotGID
		}
		if !foundPrimary || !foundSlot {
			return RuntimeAccountVerification{}, errors.New("tenant runtime account group membership is incomplete")
		}
	}
	if options.RequirePasswordLocked {
		locked := false
		for _, line := range strings.Split(string(shadow), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) < 2 || fields[0] != tenant.RuntimeUser {
				continue
			}
			locked = strings.HasPrefix(fields[1], "!") || strings.HasPrefix(fields[1], "*")
			break
		}
		if !locked {
			return RuntimeAccountVerification{}, errors.New("tenant runtime account is not password-locked")
		}
	}
	return RuntimeAccountVerification{UID: uint32(uid), GID: uint32(gid)}, nil
}
