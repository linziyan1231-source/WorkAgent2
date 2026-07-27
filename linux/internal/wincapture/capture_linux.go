//go:build linux

package wincapture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const finalConfirmationPrefix = "FINAL-WINDOWS-CAPTURE:"
const maxConcurrentReadOnlySources = 4

type captureEngine struct {
	remote      remoteTransport
	expectedUID uint32
	now         func() time.Time
}

type sourceEvidence struct {
	Summary        Summary `json:"summary"`
	ArchiveSHA256  string  `json:"archive_sha256"`
	EvidenceSHA256 string  `json:"evidence_sha256"`
	ExclusionSHA   string  `json:"exclusion_sha256"`
}

type evidenceFile struct {
	SchemaVersion int              `json:"schema_version"`
	Phase         string           `json:"phase"`
	Sources       []sourceEvidence `json:"sources"`
	OAuth         OAuthSummary     `json:"oauth_evidence"`
}

type capturedSourceEvidence struct {
	Summary       Summary `json:"summary"`
	ArchiveSHA256 string  `json:"archive_sha256"`
}

type finalManifest struct {
	SchemaVersion int                      `json:"schema_version"`
	Status        string                   `json:"status"`
	CaptureID     string                   `json:"capture_id"`
	SpecSHA256    string                   `json:"spec_sha256"`
	Before        []sourceEvidence         `json:"before"`
	Captured      []capturedSourceEvidence `json:"captured"`
	After         []sourceEvidence         `json:"after"`
	OAuthBefore   OAuthSummary             `json:"oauth_before"`
	OAuthAfter    OAuthSummary             `json:"oauth_after"`
	Aggregate     Summary                  `json:"aggregate"`
	CompletedAt   time.Time                `json:"completed_at"`
}

func Check(ctx context.Context, options CheckOptions) (Report, error) {
	if os.Geteuid() != 0 {
		return Report{}, errors.New("Windows capture checks require root")
	}
	return (&captureEngine{remote: sshTransport{}, expectedUID: 0, now: func() time.Time { return time.Now().UTC() }}).check(ctx, options)
}

func Capture(ctx context.Context, options CaptureOptions) (Report, error) {
	if os.Geteuid() != 0 {
		return Report{}, errors.New("final Windows capture requires root")
	}
	return (&captureEngine{remote: sshTransport{}, expectedUID: 0, now: func() time.Time { return time.Now().UTC() }}).capture(ctx, options)
}

func (engine *captureEngine) check(ctx context.Context, options CheckOptions) (Report, error) {
	loaded, err := loadSpec(options.SpecPath, engine.expectedUID)
	if err != nil {
		return Report{}, err
	}
	if err := verifyPrivateLocalInputs(loaded.value.LocalFiles, engine.expectedUID); err != nil {
		return Report{}, err
	}
	before, exclusionsBefore, oauthBefore, err := engine.collect(ctx, loaded.value)
	if err != nil {
		return Report{}, err
	}
	after, exclusionsAfter, oauthAfter, err := engine.collect(ctx, loaded.value)
	if err != nil {
		return Report{}, err
	}
	if err := compareCollection(before, exclusionsBefore, oauthBefore, after, exclusionsAfter, oauthAfter); err != nil {
		return Report{}, err
	}
	aggregate, err := aggregateSummaries(before)
	if err != nil || aggregate.Files > loaded.value.Limits.MaxTotalFiles || aggregate.Bytes > loaded.value.Limits.MaxTotalBytes {
		return Report{}, errors.New("read-only rehearsal exceeds aggregate capture limits")
	}
	return Report{SchemaVersion: 1, Status: "rehearsal-only-not-frozen", SpecSHA256: loaded.digest, Sources: len(before), Summary: aggregate, OAuth: oauthBefore}, nil
}

func (engine *captureEngine) capture(ctx context.Context, options CaptureOptions) (report Report, returnedErr error) {
	if !validCaptureID(options.CaptureID) || options.Confirm != finalConfirmationPrefix+options.CaptureID || !options.WindowsFrozen {
		return Report{}, errors.New("final capture requires a unique capture ID, the exact confirmation token, and an external Windows freeze declaration")
	}
	if err := validateAbsoluteFilePath(options.Destination, "capture destination"); err != nil || filepath.Base(options.Destination) != options.CaptureID {
		return Report{}, errors.New("capture destination must be an absolute path whose basename equals the capture ID")
	}
	loaded, err := loadSpec(options.SpecPath, engine.expectedUID)
	if err != nil {
		return Report{}, err
	}
	if err := verifyPrivateLocalInputs(loaded.value.LocalFiles, engine.expectedUID); err != nil {
		return Report{}, err
	}
	if existing, ok, err := readExistingCapture(options.Destination, options.CaptureID, loaded.digest, loaded.value, engine.expectedUID); err != nil {
		return Report{}, err
	} else if ok {
		return existing, nil
	}
	parent := filepath.Dir(options.Destination)
	parentFD, _, err := openPrivateRoot(parent, engine.expectedUID)
	if err != nil {
		return Report{}, errors.New("capture destination parent must be a real private 0700 directory")
	}
	defer unix.Close(parentFD)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return Report{}, errors.New("capture destination parent and its ancestors must be real directories")
	}
	free, err := statFreeBytes(parent)
	required := uint64(loaded.value.Limits.MaxCaptureBytes) + uint64(loaded.value.Limits.MinFreeBytes)
	if err != nil || free < required {
		return Report{}, errors.New("capture destination does not satisfy the configured free-space gate")
	}
	partial, err := os.MkdirTemp(parent, "."+options.CaptureID+".partial-")
	if err != nil {
		return Report{}, errors.New("create private partial capture")
	}
	if err := os.Chmod(partial, 0o700); err != nil {
		return Report{}, errors.New("secure private partial capture")
	}
	partialFD, _, err := openPrivateRoot(partial, engine.expectedUID)
	if err != nil {
		return Report{}, err
	}
	defer unix.Close(partialFD)
	failed := true
	defer func() {
		if failed {
			_ = writeFailureEvidence(partialFD, options.CaptureID, loaded.digest)
			_ = unix.Fsync(partialFD)
			_ = syncPathDirectory(parent)
		}
	}()
	if err := writePrivateJSONAt(partialFD, "journal-start.json", map[string]any{
		"schema_version": 1, "status": "in-progress", "capture_id": options.CaptureID, "spec_sha256": loaded.digest,
	}); err != nil {
		return Report{}, err
	}
	before, exclusionsBefore, oauthBefore, err := engine.collect(ctx, loaded.value)
	if err != nil {
		return Report{}, err
	}
	if err := validateAggregate(before, loaded.value.Limits); err != nil {
		return Report{}, err
	}
	if err := writePrivateJSONAt(partialFD, "evidence-before.json", makeEvidence("before", before, exclusionsBefore, oauthBefore)); err != nil {
		return Report{}, err
	}
	captured := make([]inventory, len(loaded.value.Sources))
	for index, source := range loaded.value.Sources {
		if err := ensureTarDestinationAbsent(partialFD, source.Destination); err != nil {
			return Report{}, err
		}
		captured[index], err = captureSource(ctx, engine.remote, partialFD, source, before[index], engine.expectedUID)
		if err != nil {
			return Report{}, err
		}
	}
	for _, input := range loaded.value.LocalFiles {
		if err := ensureTarDestinationAbsent(partialFD, input.Destination); err != nil {
			return Report{}, err
		}
		if err := copyPrivateLocalInput(partialFD, input, engine.expectedUID); err != nil {
			return Report{}, err
		}
	}
	after, exclusionsAfter, oauthAfter, err := engine.collect(ctx, loaded.value)
	if err != nil {
		return Report{}, err
	}
	if err := compareCollection(before, exclusionsBefore, oauthBefore, after, exclusionsAfter, oauthAfter); err != nil {
		return Report{}, err
	}
	for index := range before {
		if before[index].summary != captured[index].summary {
			return Report{}, errors.New("captured source does not match all three content inventories")
		}
	}
	if err := writePrivateJSONAt(partialFD, "evidence-after.json", makeEvidence("after", after, exclusionsAfter, oauthAfter)); err != nil {
		return Report{}, err
	}
	aggregate, err := aggregateSummaries(before)
	if err != nil {
		return Report{}, err
	}
	completed := engine.now().UTC()
	manifest := finalManifest{
		SchemaVersion: 1, Status: "complete-frozen-capture", CaptureID: options.CaptureID, SpecSHA256: loaded.digest,
		Before: evidenceSources(before, exclusionsBefore), Captured: capturedSources(captured), After: evidenceSources(after, exclusionsAfter),
		OAuthBefore: oauthBefore, OAuthAfter: oauthAfter, Aggregate: aggregate, CompletedAt: completed,
	}
	if err := writePrivateJSONAt(partialFD, "capture-manifest.json", manifest); err != nil {
		return Report{}, err
	}
	if err := syncPrivateTree(partialFD, engine.expectedUID); err != nil {
		return Report{}, err
	}
	if err := verifyStoredCapture(partialFD, loaded.value, manifest, engine.expectedUID); err != nil {
		return Report{}, errors.New("completed private capture failed pre-publication content verification")
	}
	if err := syncPathDirectory(parent); err != nil {
		return Report{}, errors.New("sync capture destination parent before publication")
	}
	if err := publishNoReplace(partial, options.Destination); err != nil {
		return Report{}, err
	}
	failed = false
	if err := syncPathDirectory(parent); err != nil {
		return Report{}, errors.New("final capture was renamed but its parent directory sync failed; verify the immutable manifest before retrying")
	}
	report = Report{SchemaVersion: 1, Status: manifest.Status, CaptureID: options.CaptureID, SpecSHA256: loaded.digest, Sources: len(before), Summary: aggregate, OAuth: oauthAfter, CompletedAt: completed}
	return report, nil
}

func (engine *captureEngine) collect(ctx context.Context, spec Spec) ([]inventory, []exclusionEvidence, OAuthSummary, error) {
	inventories := make([]inventory, len(spec.Sources))
	exclusions := make([]exclusionEvidence, len(spec.Sources))
	collectionContext, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int)
	errorsFound := make(chan error, 1)
	workers := maxConcurrentReadOnlySources
	if len(spec.Sources) < workers {
		workers = len(spec.Sources)
	}
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				parsed, exclusion, err := engine.collectSource(collectionContext, index, spec.Sources[index])
				if err != nil {
					select {
					case errorsFound <- err:
					default:
					}
					cancel()
					return
				}
				inventories[index], exclusions[index] = parsed, exclusion
			}
		}()
	}
enqueue:
	for index := range spec.Sources {
		select {
		case jobs <- index:
		case <-collectionContext.Done():
			break enqueue
		}
	}
	close(jobs)
	group.Wait()
	select {
	case err := <-errorsFound:
		return nil, nil, OAuthSummary{}, err
	default:
	}
	if err := collectionContext.Err(); err != nil {
		return nil, nil, OAuthSummary{}, errors.New("read-only Windows collection was cancelled")
	}
	var oauthOutput bytes.Buffer
	if _, err := engine.remote.run(ctx, "oauth", oauthArguments(spec.OAuthEvidence), &oauthOutput, remoteEvidenceLimit); err != nil {
		return nil, nil, OAuthSummary{}, err
	}
	oauth, err := readOAuthEvidence(oauthOutput.Bytes(), spec.OAuthEvidence)
	if err != nil {
		return nil, nil, OAuthSummary{}, fmt.Errorf("anonymous OAuth evidence is invalid: %w", err)
	}
	return inventories, exclusions, oauth, nil
}

func (engine *captureEngine) collectSource(ctx context.Context, index int, source Source) (inventory, exclusionEvidence, error) {
	var output bytes.Buffer
	if _, err := engine.remote.run(ctx, "inventory", inventoryArguments(source), &output, remoteInventoryLimit); err != nil {
		return inventory{}, exclusionEvidence{}, fmt.Errorf("anonymous source slot %d (%s) inventory failed: %w", index+1, source.Role, err)
	}
	parsed, err := readInventory(output.Bytes(), source)
	if err != nil {
		return inventory{}, exclusionEvidence{}, fmt.Errorf("anonymous source slot %d (%s) inventory evidence is invalid: %w", index+1, source.Role, err)
	}
	output.Reset()
	if _, err := engine.remote.run(ctx, "exclusions", exclusionArguments(source), &output, remoteEvidenceLimit); err != nil {
		return inventory{}, exclusionEvidence{}, fmt.Errorf("anonymous source slot %d (%s) exclusion validation failed: %w", index+1, source.Role, err)
	}
	exclusion, err := readExclusionEvidence(output.Bytes(), source)
	if err != nil {
		return inventory{}, exclusionEvidence{}, fmt.Errorf("anonymous source slot %d (%s) exclusion evidence is invalid: %w", index+1, source.Role, err)
	}
	return parsed, exclusion, nil
}

func compareCollection(before []inventory, exclusionsBefore []exclusionEvidence, oauthBefore OAuthSummary, after []inventory, exclusionsAfter []exclusionEvidence, oauthAfter OAuthSummary) error {
	if len(before) != len(after) || len(exclusionsBefore) != len(exclusionsAfter) || oauthBefore != oauthAfter {
		return errors.New("Windows sources or OAuth evidence drifted during the read-only window")
	}
	for index := range before {
		if err := compareInventories(before[index], after[index]); err != nil || exclusionsBefore[index] != exclusionsAfter[index] {
			return errors.New("Windows source or approved exclusion drifted during the read-only window")
		}
	}
	return nil
}

func validateAggregate(inventories []inventory, limits AggregateLimits) error {
	aggregate, err := aggregateSummaries(inventories)
	if err != nil || aggregate.Files > limits.MaxTotalFiles || aggregate.Bytes > limits.MaxTotalBytes {
		return errors.New("Windows source exceeds aggregate capture limits")
	}
	return nil
}

func makeEvidence(phase string, inventories []inventory, exclusions []exclusionEvidence, oauth OAuthSummary) evidenceFile {
	return evidenceFile{SchemaVersion: 1, Phase: phase, Sources: evidenceSources(inventories, exclusions), OAuth: oauth}
}

func evidenceSources(inventories []inventory, exclusions []exclusionEvidence) []sourceEvidence {
	result := make([]sourceEvidence, len(inventories))
	for index := range inventories {
		result[index] = sourceEvidence{Summary: inventories[index].summary, ArchiveSHA256: inventories[index].archiveSHA256, EvidenceSHA256: inventories[index].evidenceSHA256, ExclusionSHA: exclusions[index].SHA256}
	}
	return result
}

func capturedSources(inventories []inventory) []capturedSourceEvidence {
	result := make([]capturedSourceEvidence, len(inventories))
	for index := range inventories {
		result[index] = capturedSourceEvidence{Summary: inventories[index].summary, ArchiveSHA256: inventories[index].archiveSHA256}
	}
	return result
}

func writeFailureEvidence(rootFD int, captureID, specSHA string) error {
	return writePrivateJSONAt(rootFD, "failure.json", map[string]any{
		"schema_version": 1, "status": "failed-unpublished-partial", "capture_id": captureID, "spec_sha256": specSHA,
	})
}

func readExistingCapture(destination, captureID, specSHA string, spec Spec, expectedUID uint32) (Report, bool, error) {
	info, err := os.Lstat(destination)
	if errors.Is(err, os.ErrNotExist) {
		return Report{}, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return Report{}, false, errors.New("existing capture destination is unsafe")
	}
	rootFD, _, err := openPrivateRoot(destination, expectedUID)
	if err != nil {
		return Report{}, false, err
	}
	defer unix.Close(rootFD)
	var manifest finalManifest
	if err := readStoredStrictJSONAt(rootFD, "capture-manifest.json", 8*1024*1024, expectedUID, &manifest); err != nil ||
		manifest.SchemaVersion != 1 || manifest.Status != "complete-frozen-capture" || manifest.CaptureID != captureID || manifest.SpecSHA256 != specSHA || manifest.CompletedAt.IsZero() {
		return Report{}, false, errors.New("existing capture does not match this immutable capture request")
	}
	if err := syncPrivateTree(rootFD, expectedUID); err != nil {
		return Report{}, false, errors.New("existing capture tree failed private integrity validation")
	}
	if err := verifyStoredCapture(rootFD, spec, manifest, expectedUID); err != nil {
		return Report{}, false, err
	}
	if err := syncPathDirectory(filepath.Dir(destination)); err != nil {
		return Report{}, false, errors.New("sync existing capture destination parent")
	}
	return Report{SchemaVersion: 1, Status: manifest.Status, CaptureID: captureID, SpecSHA256: specSHA, Sources: len(manifest.Before), Summary: manifest.Aggregate, OAuth: manifest.OAuthAfter, CompletedAt: manifest.CompletedAt}, true, nil
}

func marshalPrivateJSON(value any) ([]byte, error) {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func sha256New() hashLike { return sha256.New() }

type hashLike interface {
	io.Writer
	Sum([]byte) []byte
}

func hexDigest(value hashLike) string { return hex.EncodeToString(value.Sum(nil)) }
