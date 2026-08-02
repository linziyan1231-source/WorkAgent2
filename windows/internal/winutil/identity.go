package winutil

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

type Identity struct {
	SID      string
	Username string
	Domain   string
	Elevated bool
	Admin    bool
}

func CurrentIdentity() (Identity, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &token); err != nil {
		return Identity{}, fmt.Errorf("open current process token: %w", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return Identity{}, fmt.Errorf("read current token user: %w", err)
	}
	account, domain, _, err := user.User.Sid.LookupAccount("")
	if err != nil {
		return Identity{}, fmt.Errorf("resolve current token account: %w", err)
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return Identity{}, fmt.Errorf("create Administrators SID: %w", err)
	}
	var membershipToken windows.Token
	if err := windows.DuplicateTokenEx(token, windows.TOKEN_QUERY, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &membershipToken); err != nil {
		return Identity{}, fmt.Errorf("duplicate token for membership check: %w", err)
	}
	defer membershipToken.Close()
	isAdmin, err := membershipToken.IsMember(adminSID)
	if err != nil {
		return Identity{}, fmt.Errorf("check Administrators membership: %w", err)
	}
	return Identity{SID: user.User.Sid.String(), Username: account, Domain: domain, Elevated: token.IsElevated(), Admin: isAdmin}, nil
}

func RequireIdentity(expectedSID string, requireStandardUser bool) (Identity, error) {
	id, err := CurrentIdentity()
	if err != nil {
		return Identity{}, err
	}
	if !strings.EqualFold(id.SID, expectedSID) {
		return Identity{}, fmt.Errorf("process token SID %s does not match configured SID %s", id.SID, expectedSID)
	}
	if requireStandardUser && (id.Admin || id.Elevated) {
		return Identity{}, errors.New("UserHost refuses to run with an administrator token")
	}
	return id, nil
}

func RequireAdministrator() (Identity, error) {
	identity, err := CurrentIdentity()
	if err != nil {
		return Identity{}, err
	}
	if !identity.Admin || !identity.Elevated {
		return Identity{}, errors.New("this command requires an elevated Administrators terminal")
	}
	return identity, nil
}

func VerifyWhoamiSID(ctx context.Context, expectedSID string) error {
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		return errors.New("SystemRoot is unavailable")
	}
	command := exec.CommandContext(ctx, filepath.Join(systemRoot, "System32", "whoami.exe"), "/user", "/fo", "csv", "/nh")
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("execute whoami /user: %w", err)
	}
	if len(output) > 4096 {
		return errors.New("whoami /user returned unexpected output")
	}
	reader := csv.NewReader(strings.NewReader(strings.TrimSpace(string(output))))
	row, err := reader.Read()
	if err != nil || len(row) < 2 {
		return errors.New("parse whoami /user output")
	}
	if _, err := reader.Read(); err != io.EOF {
		return errors.New("whoami /user returned multiple identities")
	}
	if !strings.EqualFold(strings.TrimSpace(row[1]), expectedSID) {
		return fmt.Errorf("whoami /user SID %s does not match configured SID %s", strings.TrimSpace(row[1]), expectedSID)
	}
	return nil
}

func LookupAccount(account string) (sid, canonical string, err error) {
	requested := account
	if strings.HasPrefix(account, `.\`) {
		computer, err := windows.ComputerName()
		if err != nil {
			return "", "", fmt.Errorf("resolve local computer name for Windows account %q: %w", requested, err)
		}
		account = computer + account[1:]
	}
	parsed, domain, accountType, err := windows.LookupSID("", account)
	if err != nil {
		return "", "", fmt.Errorf("resolve Windows account %q: %w", requested, err)
	}
	if accountType != windows.SidTypeUser {
		return "", "", fmt.Errorf("Windows account %q is not a user", requested)
	}
	name, resolvedDomain, _, err := parsed.LookupAccount("")
	if err != nil {
		return "", "", fmt.Errorf("reverse-resolve Windows account %q: %w", requested, err)
	}
	if resolvedDomain == "" {
		resolvedDomain = domain
	}
	canonical = name
	if resolvedDomain != "" {
		canonical = resolvedDomain + `\` + name
	}
	return parsed.String(), canonical, nil
}
