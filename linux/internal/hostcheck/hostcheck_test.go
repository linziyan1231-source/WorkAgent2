package hostcheck

import "testing"

func TestMountSelectionAndQuotaParsing(t *testing.T) {
	payload := "24 1 8:1 / / rw,relatime - xfs /dev/test rw,attr2,prjquota\n25 24 8:2 / /srv/workagent rw - xfs /dev/data rw,noquota\n"
	mounts, err := parseMountInfo(payload)
	if err != nil {
		t.Fatal(err)
	}
	selected, ok := mountForPath(mounts, "/srv/workagent/users")
	if !ok || selected.point != "/srv/workagent" || selected.filesystem != "xfs" {
		t.Fatalf("unexpected mount: %+v", selected)
	}
	if _, quota := selected.options["prjquota"]; quota {
		t.Fatal("quota leaked from a less-specific mount")
	}
}

func TestParsePtraceScope(t *testing.T) {
	for _, value := range []string{"0", "1", "2", "3", "2\n"} {
		if _, err := parsePtraceScope(value); err != nil {
			t.Fatalf("valid ptrace scope %q rejected: %v", value, err)
		}
	}
	for _, value := range []string{"", "-1", "4", "2 3", "invalid"} {
		if _, err := parsePtraceScope(value); err == nil {
			t.Fatalf("invalid ptrace scope %q accepted", value)
		}
	}
}
