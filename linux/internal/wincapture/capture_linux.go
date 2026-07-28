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
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	finalConfirmationPrefix      = "FINAL-WINDOWS-CAPTURE:"
	finalDeltaConfirmationPrefix = "FINAL-WINDOWS-DELTA:"
)
const maxConcurrentReadOnlySources = 4

type captureEngine struct {
	remote          remoteTransport
	expectedUID     uint32
	now             func() time.Time
	identity        identityProvider
	checkRunTimeout time.Duration
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
	SchemaVersion       int                      `json:"schema_version"`
	Status              string                   `json:"status"`
	CaptureID           string                   `json:"capture_id"`
	SpecSHA256          string                   `json:"spec_sha256"`
	RehearsalGateSHA256 string                   `json:"rehearsal_gate_sha256"`
	Before              []sourceEvidence         `json:"before"`
	Captured            []capturedSourceEvidence `json:"captured"`
	After               []sourceEvidence         `json:"after"`
	OAuthBefore         OAuthSummary             `json:"oauth_before"`
	OAuthAfter          OAuthSummary             `json:"oauth_after"`
	Aggregate           Summary                  `json:"aggregate"`
	CompletedAt         time.Time                `json:"completed_at"`
}

func Check(ctx context.Context, options CheckOptions) (Report, error) {
	if os.Geteuid() != 0 {
		return Report{}, errors.New("Windows capture checks require root")
	}
	return (&captureEngine{
		remote: sshTransport{}, expectedUID: 0, now: func() time.Time { return time.Now().UTC() }, identity: currentExecutableIdentity,
	}).check(ctx, options)
}

func Capture(ctx context.Context, options CaptureOptions) (Report, error) {
	if os.Geteuid() != 0 {
		return Report{}, errors.New("final Windows capture requires root")
	}
	return (&captureEngine{
		remote: sshTransport{}, expectedUID: 0, now: func() time.Time { return time.Now().UTC() }, identity: currentExecutableIdentity,
	}).capture(ctx, options)
}

// VerifyFinalDelta first performs a complete offline revalidation of the
// immutable capture and its private inputs. Only after every local check has
// succeeded does it contact Windows, using the same narrow read-only
// transport as a rehearsal, and require two stable collections to match the
// capture evidence exactly.
func VerifyFinalDelta(ctx context.Context, options FinalDeltaOptions) (Report, error) {
	if os.Geteuid() != 0 {
		return Report{}, errors.New("final Windows delta verification requires root")
	}
	return (&captureEngine{
		remote: sshTransport{}, expectedUID: 0, now: func() time.Time { return time.Now().UTC() }, identity: currentExecutableIdentity,
	}).verifyFinalDelta(ctx, options)
}

// VerifyCompletedCapture verifies the private spec, every pinned local input,
// the strict completion manifest and evidence documents, and the complete
// stored tree. It is intentionally local-only and cannot contact Windows.
func VerifyCompletedCapture(options CompletedCaptureOptions) (CompletedCaptureBinding, error) {
	if os.Geteuid() != 0 {
		return CompletedCaptureBinding{}, errors.New("completed Windows capture verification requires root")
	}
	binding, _, _, _, err := verifyCompletedCapture(options, 0)
	return binding, err
}

func (engine *captureEngine) capture(ctx context.Context, options CaptureOptions) (report Report, returnedErr error) {
	if !validCaptureID(options.CaptureID) || options.Confirm != finalConfirmationPrefix+options.CaptureID || !options.WindowsFrozen {
		return Report{}, errors.New("final capture requires a unique capture ID, the exact confirmation token, and an external Windows freeze declaration")
	}
	if err := validateAbsoluteFilePath(options.Destination, "capture destination"); err != nil || filepath.Base(options.Destination) != options.CaptureID {
		return Report{}, errors.New("capture destination must be an absolute path whose basename equals the capture ID")
	}
	identity, err := engine.readExecutableIdentity()
	if err != nil {
		return Report{}, err
	}
	loaded, err := loadSpec(options.SpecPath, engine.expectedUID)
	if err != nil {
		return Report{}, err
	}
	if err := verifyPrivateLocalInputs(loaded.value.LocalFiles, engine.expectedUID); err != nil {
		return Report{}, err
	}
	gate, err := readVerifiedRehearsalGate(options.RehearsalGate, engine.expectedUID)
	if err != nil {
		return Report{}, err
	}
	defer clear(gate.payload)
	if gate.value.SpecSHA256 != loaded.digest || gate.value.SourceCount != len(loaded.value.Sources) || gate.value.Executable != identity ||
		validateRehearsalGateAgainstSpec(gate.value, loaded.value) != nil {
		return Report{}, errors.New("rehearsal gate does not match the current spec and executable identity")
	}
	if existing, ok, err := readExistingCapture(options.Destination, options.CaptureID, loaded.digest, gate.digest, loaded.value, engine.expectedUID); err != nil {
		return Report{}, err
	} else if ok {
		replayedIdentity, identityErr := engine.readExecutableIdentity()
		if identityErr != nil || replayedIdentity != identity {
			return Report{}, errors.New("executable identity drifted during completed-capture replay")
		}
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
			_ = writeFailureEvidence(partialFD, options.CaptureID, loaded.digest, gate.digest)
			_ = unix.Fsync(partialFD)
			_ = syncPathDirectory(parent)
		}
	}()
	if err := writePrivateJSONAt(partialFD, "journal-start.json", map[string]any{
		"schema_version": 2, "status": "in-progress", "capture_id": options.CaptureID, "spec_sha256": loaded.digest, "rehearsal_gate_sha256": gate.digest,
	}); err != nil {
		return Report{}, err
	}
	if err := writePrivatePayloadAt(partialFD, "rehearsal-gate.json", gate.payload); err != nil {
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
	reloaded, err := loadSpec(options.SpecPath, engine.expectedUID)
	if err != nil || reloaded.digest != loaded.digest {
		return Report{}, errors.New("private capture spec drifted during final capture")
	}
	if err := verifyPrivateLocalInputs(reloaded.value.LocalFiles, engine.expectedUID); err != nil {
		return Report{}, errors.New("private local capture input drifted during final capture")
	}
	endingIdentity, err := engine.readExecutableIdentity()
	if err != nil || endingIdentity != identity {
		return Report{}, errors.New("executable identity drifted during final capture")
	}
	completed := engine.now().UTC()
	manifest := finalManifest{
		SchemaVersion: 2, Status: "complete-frozen-capture", CaptureID: options.CaptureID, SpecSHA256: loaded.digest, RehearsalGateSHA256: gate.digest,
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
	report = Report{SchemaVersion: 1, Status: manifest.Status, CaptureID: options.CaptureID, SpecSHA256: loaded.digest, RehearsalGateSHA256: gate.digest, Sources: len(before), Summary: aggregate, OAuth: oauthAfter, CompletedAt: completed}
	return report, nil
}

func (engine *captureEngine) verifyFinalDelta(ctx context.Context, options FinalDeltaOptions) (Report, error) {
	if !validCaptureID(options.CaptureID) || options.Confirm != finalDeltaConfirmationPrefix+options.CaptureID || !options.WindowsFrozen {
		return Report{}, errors.New("final delta verification requires a completed capture ID, the exact confirmation token, and an external Windows freeze declaration")
	}
	if err := validateAbsoluteFilePath(options.Destination, "capture destination"); err != nil || filepath.Base(options.Destination) != options.CaptureID {
		return Report{}, errors.New("capture destination must be an absolute path whose basename equals the capture ID")
	}

	// Nothing before this boundary can contact Windows. Keep the full local
	// integrity gate together so tests and later callers can prove deferral.
	binding, loaded, manifest, gate, err := verifyCompletedCapture(CompletedCaptureOptions{
		SpecPath: options.SpecPath, Destination: options.Destination, CaptureID: options.CaptureID,
	}, engine.expectedUID)
	if err != nil {
		return Report{}, err
	}
	identity, err := engine.readExecutableIdentity()
	if err != nil || identity != gate.Executable {
		return Report{}, errors.New("final-delta executable identity does not match the captured rehearsal gate")
	}
	preRemoteIdentity, err := engine.readExecutableIdentity()
	if err != nil || preRemoteIdentity != identity {
		return Report{}, errors.New("executable identity drifted before final-delta remote access")
	}

	first, firstExclusions, firstOAuth, err := engine.collect(ctx, loaded.value)
	if err != nil {
		return Report{}, err
	}
	second, secondExclusions, secondOAuth, err := engine.collect(ctx, loaded.value)
	if err != nil {
		return Report{}, err
	}
	if err := compareCollection(first, firstExclusions, firstOAuth, second, secondExclusions, secondOAuth); err != nil {
		return Report{}, errors.New("Windows final-delta collections are not stable")
	}
	if err := compareFinalDeltaToManifest(first, firstExclusions, firstOAuth, manifest); err != nil {
		return Report{}, err
	}
	aggregate, err := aggregateSummaries(first)
	if err != nil || aggregate != manifest.Aggregate {
		return Report{}, errors.New("Windows final-delta aggregate does not match the completed capture")
	}
	postBinding, _, _, postGate, err := verifyCompletedCapture(CompletedCaptureOptions{
		SpecPath: options.SpecPath, Destination: options.Destination, CaptureID: options.CaptureID,
	}, engine.expectedUID)
	if err != nil || postBinding != binding || postGate.Executable != identity {
		return Report{}, errors.New("completed capture changed during final-delta verification")
	}
	endingIdentity, err := engine.readExecutableIdentity()
	if err != nil || endingIdentity != identity {
		return Report{}, errors.New("executable identity drifted during final-delta verification")
	}
	captureCompletedAt := binding.CompletedAt
	return Report{
		SchemaVersion:         1,
		Status:                "complete-frozen-final-delta",
		CaptureID:             binding.CaptureID,
		SpecSHA256:            binding.SpecSHA256,
		RehearsalGateSHA256:   manifest.RehearsalGateSHA256,
		CaptureManifestSHA256: binding.CaptureManifestSHA256,
		CaptureCompletedAt:    &captureCompletedAt,
		Sources:               len(first),
		Summary:               aggregate,
		OAuth:                 firstOAuth,
		CompletedAt:           engine.now().UTC(),
	}, nil
}

func verifyCompletedCapture(options CompletedCaptureOptions, expectedUID uint32) (CompletedCaptureBinding, loadedSpec, finalManifest, rehearsalGate, error) {
	if !validCaptureID(options.CaptureID) {
		return CompletedCaptureBinding{}, loadedSpec{}, finalManifest{}, rehearsalGate{}, errors.New("completed capture ID is invalid")
	}
	if err := validateAbsoluteFilePath(options.Destination, "capture destination"); err != nil || filepath.Base(options.Destination) != options.CaptureID {
		return CompletedCaptureBinding{}, loadedSpec{}, finalManifest{}, rehearsalGate{}, errors.New("capture destination must be an absolute path whose basename equals the capture ID")
	}
	parentFD, _, err := openPrivateRoot(filepath.Dir(options.Destination), expectedUID)
	if err != nil {
		return CompletedCaptureBinding{}, loadedSpec{}, finalManifest{}, rehearsalGate{}, errors.New("capture destination parent must be a real private 0700 directory")
	}
	if err := unix.Close(parentFD); err != nil {
		return CompletedCaptureBinding{}, loadedSpec{}, finalManifest{}, rehearsalGate{}, errors.New("close capture destination parent")
	}
	loaded, err := loadSpec(options.SpecPath, expectedUID)
	if err != nil {
		return CompletedCaptureBinding{}, loadedSpec{}, finalManifest{}, rehearsalGate{}, err
	}
	if err := verifyPrivateLocalInputs(loaded.value.LocalFiles, expectedUID); err != nil {
		return CompletedCaptureBinding{}, loadedSpec{}, finalManifest{}, rehearsalGate{}, err
	}
	manifest, gate, manifestDigest, err := readAndVerifyExistingCapture(options.Destination, options.CaptureID, loaded.digest, loaded.value, expectedUID)
	if err != nil {
		return CompletedCaptureBinding{}, loadedSpec{}, finalManifest{}, rehearsalGate{}, err
	}
	reloaded, err := loadSpec(options.SpecPath, expectedUID)
	if err != nil || reloaded.digest != loaded.digest {
		return CompletedCaptureBinding{}, loadedSpec{}, finalManifest{}, rehearsalGate{}, errors.New("capture spec changed during completed-capture verification")
	}
	if err := verifyPrivateLocalInputs(reloaded.value.LocalFiles, expectedUID); err != nil {
		return CompletedCaptureBinding{}, loadedSpec{}, finalManifest{}, rehearsalGate{}, errors.New("private local input changed during completed-capture verification")
	}
	binding := CompletedCaptureBinding{
		SchemaVersion: 1, CaptureID: manifest.CaptureID, SpecSHA256: manifest.SpecSHA256,
		CaptureManifestSHA256: manifestDigest, CompletedAt: manifest.CompletedAt, Aggregate: manifest.Aggregate,
	}
	return binding, loaded, manifest, gate, nil
}

func compareFinalDeltaToManifest(inventories []inventory, exclusions []exclusionEvidence, oauth OAuthSummary, manifest finalManifest) error {
	if len(inventories) != len(manifest.Before) || len(inventories) != len(manifest.After) || len(exclusions) != len(inventories) ||
		oauth != manifest.OAuthBefore || oauth != manifest.OAuthAfter {
		return errors.New("Windows final-delta OAuth or source cardinality does not match the completed capture")
	}
	current := evidenceSources(inventories, exclusions)
	if !equalSourceEvidence(current, manifest.Before) || !equalSourceEvidence(current, manifest.After) {
		return errors.New("Windows final-delta source or approved-exclusion evidence does not match the completed capture")
	}
	return nil
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
	drift := make([]string, 0, 6)
	if len(before) != len(after) || len(exclusionsBefore) != len(exclusionsAfter) || len(before) != len(exclusionsBefore) {
		drift = append(drift, "cardinality")
	}
	if oauthBefore.Files != oauthAfter.Files {
		drift = append(drift, "oauth-file-count")
	}
	if oauthBefore.Bytes != oauthAfter.Bytes {
		drift = append(drift, "oauth-aggregate-bytes")
	}
	if oauthBefore.SHA256 != oauthAfter.SHA256 {
		drift = append(drift, "oauth-digest")
	}
	comparisonCount := min(len(before), len(after), len(exclusionsBefore), len(exclusionsAfter))
	sourceSlots := make([]string, 0)
	exclusionSlots := make([]string, 0)
	for index := range comparisonCount {
		if err := compareInventories(before[index], after[index]); err != nil {
			sourceSlots = append(sourceSlots, strconv.Itoa(index+1))
		}
		if exclusionsBefore[index] != exclusionsAfter[index] {
			exclusionSlots = append(exclusionSlots, strconv.Itoa(index+1))
		}
	}
	if len(sourceSlots) > 0 {
		drift = append(drift, "source-slots="+strings.Join(sourceSlots, ","))
	}
	if len(exclusionSlots) > 0 {
		drift = append(drift, "approved-exclusion-slots="+strings.Join(exclusionSlots, ","))
	}
	if len(drift) > 0 {
		return errors.New("Windows sources or OAuth evidence drifted during the read-only window: " + strings.Join(drift, "; "))
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

func writeFailureEvidence(rootFD int, captureID, specSHA, gateSHA string) error {
	return writePrivateJSONAt(rootFD, "failure.json", map[string]any{
		"schema_version": 2, "status": "failed-unpublished-partial", "capture_id": captureID, "spec_sha256": specSHA, "rehearsal_gate_sha256": gateSHA,
	})
}

func readExistingCapture(destination, captureID, specSHA, gateSHA string, spec Spec, expectedUID uint32) (Report, bool, error) {
	info, err := os.Lstat(destination)
	if errors.Is(err, os.ErrNotExist) {
		return Report{}, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return Report{}, false, errors.New("existing capture destination is unsafe")
	}
	manifest, _, _, err := readAndVerifyExistingCapture(destination, captureID, specSHA, spec, expectedUID)
	if err != nil {
		return Report{}, false, err
	}
	if manifest.RehearsalGateSHA256 != gateSHA {
		return Report{}, false, errors.New("existing capture is bound to a different rehearsal gate")
	}
	return Report{SchemaVersion: 1, Status: manifest.Status, CaptureID: captureID, SpecSHA256: specSHA, RehearsalGateSHA256: gateSHA, Sources: len(manifest.Before), Summary: manifest.Aggregate, OAuth: manifest.OAuthAfter, CompletedAt: manifest.CompletedAt}, true, nil
}

func readAndVerifyExistingCapture(destination, captureID, specSHA string, spec Spec, expectedUID uint32) (finalManifest, rehearsalGate, string, error) {
	rootFD, _, err := openPrivateRoot(destination, expectedUID)
	if err != nil {
		return finalManifest{}, rehearsalGate{}, "", err
	}
	defer unix.Close(rootFD)
	var manifest finalManifest
	manifestDigest, manifestErr := readStoredCanonicalJSONAtDigest(rootFD, "capture-manifest.json", 8*1024*1024, expectedUID, &manifest)
	if manifestErr != nil ||
		manifest.SchemaVersion != 2 || manifest.Status != "complete-frozen-capture" || manifest.CaptureID != captureID || manifest.SpecSHA256 != specSHA ||
		!sha256Pattern.MatchString(manifest.RehearsalGateSHA256) || manifest.CompletedAt.IsZero() {
		return finalManifest{}, rehearsalGate{}, "", errors.New("existing capture does not match this immutable capture request")
	}
	if err := syncPrivateTree(rootFD, expectedUID); err != nil {
		return finalManifest{}, rehearsalGate{}, "", errors.New("existing capture tree failed private integrity validation")
	}
	if err := verifyStoredCapture(rootFD, spec, manifest, expectedUID); err != nil {
		return finalManifest{}, rehearsalGate{}, "", err
	}
	var finalManifestRead finalManifest
	finalDigest, err := readStoredCanonicalJSONAtDigest(rootFD, "capture-manifest.json", 8*1024*1024, expectedUID, &finalManifestRead)
	if err != nil || finalDigest != manifestDigest {
		return finalManifest{}, rehearsalGate{}, "", errors.New("existing capture manifest changed during verification")
	}
	var finalGateRead rehearsalGate
	finalGateDigest, err := readStoredCanonicalJSONAtDigest(rootFD, "rehearsal-gate.json", maxRehearsalMetadataBytes, expectedUID, &finalGateRead)
	if err != nil || finalGateDigest != manifest.RehearsalGateSHA256 || validateRehearsalGate(finalGateRead) != nil {
		return finalManifest{}, rehearsalGate{}, "", errors.New("existing capture rehearsal gate changed during verification")
	}
	if err := syncPathDirectory(filepath.Dir(destination)); err != nil {
		return finalManifest{}, rehearsalGate{}, "", errors.New("sync existing capture destination parent")
	}
	return manifest, finalGateRead, manifestDigest, nil
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
