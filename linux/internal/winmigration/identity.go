package winmigration

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

var (
	windowsSIDPattern = regexp.MustCompile(`^S-[0-9]+(?:-[0-9]+)+$`)
	tenantNamespace   = uuid.MustParse("983a6aa1-d6b5-5a98-91d4-e2a131cd5569")
)

func deriveIdentity(sid, tenantDataRoot string) (tenantID, runtimeUser, dataRoot string, projectID uint32, err error) {
	sid = strings.ToUpper(strings.TrimSpace(sid))
	if !windowsSIDPattern.MatchString(sid) {
		return "", "", "", 0, errors.New("Windows SID has an invalid canonical form")
	}
	tenant := uuid.NewSHA1(tenantNamespace, []byte(sid)).String()
	digest := sha256.Sum256([]byte("workagent/windows-tenant/v1\x00" + sid))
	encoded := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:]))
	runtime := "workagent_" + encoded[:26]
	project := binary.BigEndian.Uint32(digest[20:24]) & 0x3fffffff
	if project < 10_000 {
		project += 10_000
	}
	return tenant, runtime, filepathJoin(tenantDataRoot, tenant), project, nil
}

// filepathJoin is kept separate to make the deterministic identity calculation
// explicit while still using the host's canonical Linux path separator.
func filepathJoin(root, child string) string {
	return strings.TrimSuffix(root, "/") + "/" + child
}

func validateIdentityCollisions(tenants []plannedTenant) error {
	tenantIDs := make(map[string]string, len(tenants))
	runtimeUsers := make(map[string]string, len(tenants))
	dataRoots := make(map[string]string, len(tenants))
	projectIDs := make(map[uint32]string, len(tenants))
	for _, tenant := range tenants {
		sid := tenant.user.WindowsSID
		for _, item := range []struct {
			label string
			value string
			seen  map[string]string
		}{
			{"tenant UUID", tenant.report.TenantID, tenantIDs},
			{"runtime user", tenant.report.RuntimeUser, runtimeUsers},
			{"data root", tenant.report.DataRoot, dataRoots},
		} {
			if other, exists := item.seen[item.value]; exists && other != sid {
				return fmt.Errorf("deterministic %s collision detected", item.label)
			}
			item.seen[item.value] = sid
		}
		if other, exists := projectIDs[tenant.report.ProjectID]; exists && other != sid {
			return errors.New("deterministic XFS project ID collision detected")
		}
		projectIDs[tenant.report.ProjectID] = sid
	}
	return nil
}
