//go:build linux

package wincapture

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

type postCollectionTransport struct {
	remoteTransport
	oauthCalls int
	after      func()
}

func (transport *postCollectionTransport) run(ctx context.Context, action string, arguments []string, output io.Writer, limit int64) (stderrSummary, error) {
	summary, err := transport.remoteTransport.run(ctx, action, arguments, output, limit)
	if err == nil && action == "oauth" {
		transport.oauthCalls++
		if transport.oauthCalls == 2 {
			transport.after()
		}
	}
	return summary, err
}

func TestCompareCollectionReportsAnonymousDriftClass(t *testing.T) {
	makeEvidence := func() ([]inventory, []exclusionEvidence, OAuthSummary) {
		return []inventory{{
				summary:        Summary{Files: 1, Bytes: 2, SHA256: strings.Repeat("a", 64)},
				archiveSHA256:  strings.Repeat("b", 64),
				evidenceSHA256: strings.Repeat("c", 64),
			}}, []exclusionEvidence{{SHA256: strings.Repeat("d", 64)}}, OAuthSummary{
				Files: 1, Bytes: 2, SHA256: strings.Repeat("e", 64),
			}
	}

	tests := []struct {
		name string
		want string
		edit func(*[]inventory, *[]exclusionEvidence, *OAuthSummary)
	}{
		{
			name: "cardinality",
			want: "Windows sources or OAuth evidence drifted during the read-only window: cardinality",
			edit: func(after *[]inventory, _ *[]exclusionEvidence, _ *OAuthSummary) { *after = nil },
		},
		{
			name: "oauth-files",
			want: "Windows sources or OAuth evidence drifted during the read-only window: oauth-file-count",
			edit: func(_ *[]inventory, _ *[]exclusionEvidence, oauth *OAuthSummary) { oauth.Files++ },
		},
		{
			name: "oauth-bytes",
			want: "Windows sources or OAuth evidence drifted during the read-only window: oauth-aggregate-bytes",
			edit: func(_ *[]inventory, _ *[]exclusionEvidence, oauth *OAuthSummary) { oauth.Bytes++ },
		},
		{
			name: "oauth-digest",
			want: "Windows sources or OAuth evidence drifted during the read-only window: oauth-digest",
			edit: func(_ *[]inventory, _ *[]exclusionEvidence, oauth *OAuthSummary) {
				oauth.SHA256 = strings.Repeat("f", 64)
			},
		},
		{
			name: "source",
			want: "Windows sources or OAuth evidence drifted during the read-only window: source-slots=1",
			edit: func(after *[]inventory, _ *[]exclusionEvidence, _ *OAuthSummary) { (*after)[0].summary.Bytes++ },
		},
		{
			name: "exclusion",
			want: "Windows sources or OAuth evidence drifted during the read-only window: approved-exclusion-slots=1",
			edit: func(_ *[]inventory, exclusions *[]exclusionEvidence, _ *OAuthSummary) {
				(*exclusions)[0].SHA256 = strings.Repeat("f", 64)
			},
		},
		{
			name: "combined",
			want: "Windows sources or OAuth evidence drifted during the read-only window: oauth-aggregate-bytes; oauth-digest; source-slots=1; approved-exclusion-slots=1",
			edit: func(after *[]inventory, exclusions *[]exclusionEvidence, oauth *OAuthSummary) {
				oauth.Bytes++
				oauth.SHA256 = strings.Repeat("f", 64)
				(*after)[0].summary.Bytes++
				(*exclusions)[0].SHA256 = strings.Repeat("f", 64)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before, exclusionsBefore, oauthBefore := makeEvidence()
			after, exclusionsAfter, oauthAfter := makeEvidence()
			test.edit(&after, &exclusionsAfter, &oauthAfter)
			err := compareCollection(before, exclusionsBefore, oauthBefore, after, exclusionsAfter, oauthAfter)
			if err == nil || err.Error() != test.want {
				t.Fatalf("drift error = %v, want %q", err, test.want)
			}
			for _, secret := range []string{oauthBefore.SHA256, before[0].summary.SHA256, before[0].archiveSHA256, exclusionsBefore[0].SHA256} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("anonymous drift error exposed evidence digest: %v", err)
				}
			}
		})
	}
}

func TestCheckReportHasRealCompletionTime(t *testing.T) {
	spec := validSpec(t)
	parent := privateTemp(t)
	specPath := writeSpec(t, parent, spec)
	completed := time.Unix(1_900_000_123, 0).UTC()
	nowCalls := 0
	engine := &captureEngine{
		remote:      newFixtureTransport(t, spec),
		expectedUID: uint32(os.Geteuid()),
		now: func() time.Time {
			nowCalls++
			if nowCalls == 1 {
				return completed.Add(-time.Minute)
			}
			return completed
		},
		identity: fixtureIdentityProvider,
	}
	report, err := engine.check(context.Background(), testCheckOptions(t, parent, specPath, "fixture-rehearsal-completion"))
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "rehearsal-only-not-frozen" || report.CompletedAt.IsZero() || !report.CompletedAt.Equal(completed) {
		t.Fatalf("rehearsal completion evidence is not auditable: %#v", report)
	}
}

func TestCheckRejectsSpecDriftAfterRemoteCollections(t *testing.T) {
	spec := validSpec(t)
	parent := privateTemp(t)
	specPath := writeSpec(t, parent, spec)
	transport := &postCollectionTransport{remoteTransport: newFixtureTransport(t, spec)}
	transport.after = func() {
		file, err := os.OpenFile(specPath, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteString("\n"); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	engine := &captureEngine{remote: transport, expectedUID: uint32(os.Geteuid()), now: time.Now, identity: fixtureIdentityProvider}
	if _, err := engine.check(context.Background(), testCheckOptions(t, parent, specPath, "fixture-rehearsal-spec-drift")); err == nil || !strings.Contains(err.Error(), "spec drifted") {
		t.Fatalf("post-collection spec drift was accepted: %v", err)
	}
}
