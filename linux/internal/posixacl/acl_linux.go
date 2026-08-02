package posixacl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const (
	aclXattrVersion = 2
	aclUserObjTag   = 0x01
	aclUserTag      = 0x02
	aclGroupObjTag  = 0x04
	aclGroupTag     = 0x08
	aclMaskTag      = 0x10
	aclOtherTag     = 0x20
	aclUndefinedID  = ^uint32(0)
)

// UserPermissions returns the effective rwx permission bits for a named user
// entry in the file's POSIX access ACL. Linux stores ACL entries in the
// system.posix_acl_access extended attribute.
func UserPermissions(path string, uid uint32) (os.FileMode, error) {
	payload, err := readAccessACL(path)
	if err != nil {
		return 0, err
	}
	return userPermissions(payload, uid)
}

// VerifyExclusiveUserPermissions requires the only named ACL principal to be
// the expected UID. It is used for a tenant's fixed configuration file so an
// accidentally retained ACL cannot disclose that configuration to another
// tenant account.
func VerifyExclusiveUserPermissions(path string, uid uint32, expected os.FileMode) error {
	payload, err := readAccessACL(path)
	if err != nil {
		return err
	}
	return verifyExclusiveUserPermissions(payload, uid, expected)
}

// VerifyExclusiveUserPermissionsFD is the descriptor-bound form used while a
// transaction inode is still anonymous.
func VerifyExclusiveUserPermissionsFD(fd int, uid uint32, expected os.FileMode) error {
	payload, err := readAccessACLFD(fd)
	if err != nil {
		return err
	}
	return verifyExclusiveUserPermissions(payload, uid, expected)
}

// SetExclusiveUserPermissionsFD installs the canonical WorkAgent file ACL on
// an already-open descriptor. Descriptor-based authoring lets callers finish
// an anonymous O_TMPFILE inode before making any pathname visible.
func SetExclusiveUserPermissionsFD(fd int, uid uint32, permissions os.FileMode) error {
	if fd < 0 || uid == aclUndefinedID || permissions.Perm()&^os.FileMode(0o7) != 0 {
		return errors.New("POSIX ACL descriptor, user, or permissions are invalid")
	}
	payload := make([]byte, 4+5*8)
	binary.LittleEndian.PutUint32(payload[:4], aclXattrVersion)
	entries := []struct {
		tag        uint16
		permission uint16
		id         uint32
	}{
		{aclUserObjTag, 0o6, aclUndefinedID},
		{aclUserTag, uint16(permissions.Perm()), uid},
		{aclGroupObjTag, 0o4, aclUndefinedID},
		{aclMaskTag, uint16(permissions.Perm()), aclUndefinedID},
		{aclOtherTag, 0, aclUndefinedID},
	}
	for index, entry := range entries {
		offset := 4 + index*8
		binary.LittleEndian.PutUint16(payload[offset:offset+2], entry.tag)
		binary.LittleEndian.PutUint16(payload[offset+2:offset+4], entry.permission)
		binary.LittleEndian.PutUint32(payload[offset+4:offset+8], entry.id)
	}
	if err := unix.Fsetxattr(fd, "system.posix_acl_access", payload, 0); err != nil {
		return fmt.Errorf("set exclusive POSIX ACL: %w", err)
	}
	return nil
}

func verifyExclusiveUserPermissions(payload []byte, uid uint32, expected os.FileMode) error {
	parsed, err := parseAccessACL(payload)
	if err != nil {
		return err
	}
	permission, found := parsed.users[uid]
	if !found || len(parsed.users) != 1 || len(parsed.groups) != 0 {
		return errors.New("POSIX ACL contains an unexpected named principal")
	}
	if os.FileMode(permission&parsed.mask).Perm() != expected.Perm() {
		return errors.New("POSIX ACL named-user permission does not match policy")
	}
	return nil
}

func userPermissions(payload []byte, uid uint32) (os.FileMode, error) {
	parsed, err := parseAccessACL(payload)
	if err != nil {
		return 0, err
	}
	permission, found := parsed.users[uid]
	if !found {
		return 0, errors.New("POSIX ACL is missing the required named user entry")
	}
	return os.FileMode(permission & parsed.mask), nil
}

type accessACL struct {
	users  map[uint32]uint16
	groups map[uint32]uint16
	mask   uint16
}

func readAccessACL(path string) ([]byte, error) {
	size, err := unix.Getxattr(path, "system.posix_acl_access", nil)
	if err != nil {
		return nil, fmt.Errorf("read POSIX ACL size: %w", err)
	}
	if size < 4 || size > 64*1024 {
		return nil, errors.New("POSIX ACL has an invalid size")
	}
	payload := make([]byte, size)
	read, err := unix.Getxattr(path, "system.posix_acl_access", payload)
	if err != nil {
		return nil, fmt.Errorf("read POSIX ACL: %w", err)
	}
	if read != size {
		return nil, errors.New("POSIX ACL changed while it was read")
	}
	return payload, nil
}

func readAccessACLFD(fd int) ([]byte, error) {
	if fd < 0 {
		return nil, errors.New("POSIX ACL descriptor is invalid")
	}
	size, err := unix.Fgetxattr(fd, "system.posix_acl_access", nil)
	if err != nil {
		return nil, fmt.Errorf("read POSIX ACL descriptor size: %w", err)
	}
	if size < 4 || size > 64*1024 {
		return nil, errors.New("POSIX ACL descriptor has an invalid size")
	}
	payload := make([]byte, size)
	read, err := unix.Fgetxattr(fd, "system.posix_acl_access", payload)
	if err != nil {
		return nil, fmt.Errorf("read POSIX ACL descriptor: %w", err)
	}
	if read != size {
		return nil, errors.New("POSIX ACL descriptor changed while it was read")
	}
	return payload, nil
}

func parseAccessACL(payload []byte) (accessACL, error) {
	if len(payload) < 4 || (len(payload)-4)%8 != 0 || binary.LittleEndian.Uint32(payload[:4]) != aclXattrVersion {
		return accessACL{}, errors.New("POSIX ACL encoding is invalid")
	}
	parsed := accessACL{users: make(map[uint32]uint16), groups: make(map[uint32]uint16)}
	baseEntries := make(map[uint16]bool, 4)
	for offset := 4; offset < len(payload); offset += 8 {
		tag := binary.LittleEndian.Uint16(payload[offset : offset+2])
		value := binary.LittleEndian.Uint16(payload[offset+2 : offset+4])
		id := binary.LittleEndian.Uint32(payload[offset+4 : offset+8])
		if value&^uint16(7) != 0 {
			return accessACL{}, errors.New("POSIX ACL contains invalid permission bits")
		}
		switch tag {
		case aclUserObjTag, aclGroupObjTag, aclOtherTag:
			if id != aclUndefinedID || baseEntries[tag] {
				return accessACL{}, errors.New("POSIX ACL contains an invalid or duplicate base entry")
			}
			baseEntries[tag] = true
		case aclUserTag:
			if id == aclUndefinedID {
				return accessACL{}, errors.New("POSIX ACL contains an invalid user entry")
			}
			if _, duplicate := parsed.users[id]; duplicate {
				return accessACL{}, errors.New("POSIX ACL contains a duplicate user entry")
			}
			parsed.users[id] = value
		case aclGroupTag:
			if id == aclUndefinedID {
				return accessACL{}, errors.New("POSIX ACL contains an invalid group entry")
			}
			if _, duplicate := parsed.groups[id]; duplicate {
				return accessACL{}, errors.New("POSIX ACL contains a duplicate group entry")
			}
			parsed.groups[id] = value
		case aclMaskTag:
			if id != aclUndefinedID || baseEntries[tag] {
				return accessACL{}, errors.New("POSIX ACL contains an invalid or duplicate mask")
			}
			parsed.mask, baseEntries[tag] = value, true
		default:
			return accessACL{}, errors.New("POSIX ACL contains an unknown entry type")
		}
	}
	for _, tag := range []uint16{aclUserObjTag, aclGroupObjTag, aclMaskTag, aclOtherTag} {
		if !baseEntries[tag] {
			return accessACL{}, errors.New("POSIX ACL is missing a required base entry")
		}
	}
	return parsed, nil
}
