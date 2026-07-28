//go:build linux

package wincapture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	rehearsalReceiptSchemaVersion = 1
	rehearsalGateSchemaVersion    = 1
	rehearsalCollectionCount      = 2
	rehearsalGateReceiptCount     = 3
	defaultRehearsalRunTimeout    = 24 * time.Hour
	maxRehearsalMetadataBytes     = 16 * 1024 * 1024
)

var vcsRevisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

const captureCommandModulePath = "github.com/linziyan1231-source/WorkAgent2/linux/cmd/workagent-capture-windows"

type executableIdentity struct {
	VCSRevision string `json:"vcs_revision"`
	SHA256      string `json:"sha256"`
}

type identityProvider func() (executableIdentity, error)

// rehearsalCollectionEvidence is complete anonymous evidence for one remote
// collection. Slots preserve spec ordering but deliberately contain no source
// IDs, source paths, destination leaves, exclusion paths, or OAuth filenames.
type rehearsalCollectionEvidence struct {
	Sources   []sourceEvidence `json:"sources"`
	OAuth     OAuthSummary     `json:"oauth_evidence"`
	Aggregate Summary          `json:"aggregate"`
}

type rehearsalCollectionRecord struct {
	Evidence rehearsalCollectionEvidence `json:"evidence"`
	SHA256   string                      `json:"sha256"`
}

type rehearsalReceipt struct {
	SchemaVersion     int                         `json:"schema_version"`
	Status            string                      `json:"status"`
	RehearsalID       string                      `json:"rehearsal_id"`
	WritersQuiesced   bool                        `json:"writers_quiesced"`
	ConfirmationClass string                      `json:"confirmation_class"`
	SpecSHA256        string                      `json:"spec_sha256"`
	Executable        executableIdentity          `json:"executable"`
	SourceCount       int                         `json:"source_count"`
	CollectionCount   int                         `json:"collection_count"`
	StartedAt         time.Time                   `json:"started_at"`
	CompletedAt       time.Time                   `json:"completed_at"`
	Collections       []rehearsalCollectionRecord `json:"collections"`
}

type rehearsalReceiptBinding struct {
	Receipt       rehearsalReceipt `json:"receipt"`
	ReceiptSHA256 string           `json:"receipt_sha256"`
}

type rehearsalGate struct {
	SchemaVersion   int                       `json:"schema_version"`
	Status          string                    `json:"status"`
	SpecSHA256      string                    `json:"spec_sha256"`
	Executable      executableIdentity        `json:"executable"`
	SourceCount     int                       `json:"source_count"`
	ReceiptCount    int                       `json:"receipt_count"`
	CollectionCount int                       `json:"collection_count_per_receipt"`
	CrossRunState   string                    `json:"cross_run_state"`
	Receipts        []rehearsalReceiptBinding `json:"receipts"`
	SealedAt        time.Time                 `json:"sealed_at"`
}

// RehearsalGateReport is anonymous stdout evidence for a local gate seal.
type RehearsalGateReport struct {
	SchemaVersion int       `json:"schema_version"`
	Status        string    `json:"status"`
	SpecSHA256    string    `json:"spec_sha256"`
	GateSHA256    string    `json:"rehearsal_gate_sha256"`
	SourceCount   int       `json:"source_count"`
	ReceiptCount  int       `json:"receipt_count"`
	CrossRunState string    `json:"cross_run_state"`
	CompletedAt   time.Time `json:"completed_at"`
}

type verifiedRehearsalGate struct {
	value   rehearsalGate
	payload []byte
	digest  string
}

func currentExecutableIdentity() (executableIdentity, error) {
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		return executableIdentity{}, errors.New("open current executable")
	}
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size < 1 ||
		before.Uid != 0 || before.Gid != 0 || before.Nlink != 1 || os.FileMode(before.Mode).Perm() != 0o500 {
		return executableIdentity{}, errors.New("current executable is not the supported root-owned 0500 release file")
	}
	info, err := buildinfo.Read(file)
	if err != nil || info.Path != captureCommandModulePath {
		return executableIdentity{}, errors.New("read capture-command executable build identity")
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		if strings.HasPrefix(setting.Key, "vcs") {
			if _, exists := settings[setting.Key]; exists {
				return executableIdentity{}, errors.New("executable contains duplicate VCS build settings")
			}
			settings[setting.Key] = setting.Value
		}
	}
	revision := settings["vcs.revision"]
	if settings["vcs"] != "git" || settings["vcs.modified"] != "false" || !vcsRevisionPattern.MatchString(revision) {
		return executableIdentity{}, errors.New("executable must have one clean Git VCS revision")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return executableIdentity{}, errors.New("seek current executable")
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, file)
	var after unix.Stat_t
	if statErr := unix.Fstat(int(file.Fd()), &after); err != nil || statErr != nil || written != before.Size || !stableFileStat(before, after) {
		return executableIdentity{}, errors.New("current executable changed while it was hashed")
	}
	return executableIdentity{VCSRevision: revision, SHA256: hex.EncodeToString(hasher.Sum(nil))}, nil
}

func validExecutableIdentity(identity executableIdentity) bool {
	return vcsRevisionPattern.MatchString(identity.VCSRevision) && sha256Pattern.MatchString(identity.SHA256)
}

func (engine *captureEngine) readExecutableIdentity() (executableIdentity, error) {
	if engine.identity == nil {
		return executableIdentity{}, errors.New("executable identity provider is unavailable")
	}
	identity, err := engine.identity()
	if err != nil || !validExecutableIdentity(identity) {
		return executableIdentity{}, errors.New("executable identity is invalid")
	}
	return identity, nil
}

func (engine *captureEngine) rehearsalTimeout() time.Duration {
	if engine.checkRunTimeout > 0 {
		return engine.checkRunTimeout
	}
	return defaultRehearsalRunTimeout
}

func (engine *captureEngine) check(ctx context.Context, options CheckOptions) (Report, error) {
	runContext, cancel := context.WithTimeout(ctx, engine.rehearsalTimeout())
	defer cancel()
	if !validCaptureID(options.RehearsalID) || !options.WritersQuiesced || options.Confirm != "REHEARSAL-WRITERS-QUIESCED:"+options.RehearsalID {
		return Report{}, errors.New("read-only rehearsal requires a safe ID, an external writer-quiescence declaration, and the exact confirmation token")
	}
	parentFD, err := preparePrivateNoReplaceOutput(options.ReceiptOutput, "rehearsal receipt", engine.expectedUID)
	if err != nil {
		return Report{}, err
	}
	defer unix.Close(parentFD)
	if err := unix.Flock(parentFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return Report{}, errors.New("another rehearsal is active in the private receipt directory")
	}
	defer unix.Flock(parentFD, unix.LOCK_UN)

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
	remoteRun, err := engine.bindRemoteSession(loaded.value.SSHTransport)
	if err != nil {
		return Report{}, err
	}
	defer remoteRun.close()

	if err := runContext.Err(); err != nil {
		return Report{}, rehearsalCollectionError(runContext, err)
	}
	started := engine.now().UTC()
	first, firstExclusions, firstOAuth, err := engine.collect(runContext, loaded.value)
	if err != nil {
		return Report{}, rehearsalCollectionError(runContext, err)
	}
	second, secondExclusions, secondOAuth, err := engine.collect(runContext, loaded.value)
	if err != nil {
		return Report{}, rehearsalCollectionError(runContext, err)
	}
	if err := compareCollection(first, firstExclusions, firstOAuth, second, secondExclusions, secondOAuth); err != nil {
		return Report{}, err
	}
	aggregate, err := aggregateSummaries(first)
	if err != nil || aggregate.Files > loaded.value.Limits.MaxTotalFiles || aggregate.Bytes > loaded.value.Limits.MaxTotalBytes {
		return Report{}, errors.New("read-only rehearsal exceeds aggregate capture limits")
	}
	reloaded, err := loadSpec(options.SpecPath, engine.expectedUID)
	if err != nil || reloaded.digest != loaded.digest {
		return Report{}, errors.New("private capture spec drifted during the read-only rehearsal")
	}
	if err := verifyPrivateLocalInputs(reloaded.value.LocalFiles, engine.expectedUID); err != nil {
		return Report{}, errors.New("private local capture input drifted during the read-only rehearsal")
	}
	if err := remoteRun.verify(); err != nil {
		return Report{}, errors.New("private SSH transport binding drifted during the read-only rehearsal")
	}
	if err := remoteRun.close(); err != nil {
		return Report{}, errors.New("close immutable SSH transport session after the read-only rehearsal")
	}
	endingIdentity, err := engine.readExecutableIdentity()
	if err != nil || endingIdentity != identity {
		return Report{}, errors.New("executable identity drifted during the read-only rehearsal")
	}
	if err := runContext.Err(); err != nil {
		return Report{}, rehearsalCollectionError(runContext, err)
	}
	completed := engine.now().UTC()
	if started.IsZero() || !completed.After(started) {
		return Report{}, errors.New("read-only rehearsal UTC interval is invalid")
	}

	firstEvidence := makeRehearsalCollection(first, firstExclusions, firstOAuth, aggregate)
	secondEvidence := makeRehearsalCollection(second, secondExclusions, secondOAuth, aggregate)
	firstRecord, err := makeRehearsalCollectionRecord(firstEvidence)
	if err != nil {
		return Report{}, errors.New("encode anonymous rehearsal collection evidence")
	}
	secondRecord, err := makeRehearsalCollectionRecord(secondEvidence)
	if err != nil || firstRecord.SHA256 != secondRecord.SHA256 || !equalRehearsalCollectionEvidence(firstRecord.Evidence, secondRecord.Evidence) {
		return Report{}, errors.New("anonymous rehearsal collection evidence does not converge")
	}
	receipt := rehearsalReceipt{
		SchemaVersion: rehearsalReceiptSchemaVersion, Status: "complete-read-only-rehearsal",
		RehearsalID: options.RehearsalID, WritersQuiesced: true, ConfirmationClass: "REHEARSAL-WRITERS-QUIESCED",
		SpecSHA256: loaded.digest, Executable: identity, SourceCount: len(first),
		CollectionCount: rehearsalCollectionCount, StartedAt: started, CompletedAt: completed,
		Collections: []rehearsalCollectionRecord{firstRecord, secondRecord},
	}
	payload, err := marshalPrivateJSON(receipt)
	if err != nil {
		return Report{}, errors.New("encode private rehearsal receipt")
	}
	defer clear(payload)
	receiptDigest := sha256Bytes(payload)
	if err := runContext.Err(); err != nil {
		return Report{}, rehearsalCollectionError(runContext, err)
	}
	if err := writePrivatePayloadNoReplaceAt(parentFD, options.ReceiptOutput, payload, "rehearsal receipt", engine.expectedUID); err != nil {
		return Report{}, err
	}
	return Report{
		SchemaVersion: 1, Status: "rehearsal-only-not-frozen", SpecSHA256: loaded.digest,
		RehearsalReceiptSHA256: receiptDigest, Sources: len(first), Summary: aggregate,
		OAuth: firstOAuth, CompletedAt: completed,
	}, nil
}

func rehearsalCollectionError(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errors.New("read-only rehearsal exceeded its run-level time limit")
	}
	return err
}

func makeRehearsalCollection(inventories []inventory, exclusions []exclusionEvidence, oauth OAuthSummary, aggregate Summary) rehearsalCollectionEvidence {
	return rehearsalCollectionEvidence{Sources: evidenceSources(inventories, exclusions), OAuth: oauth, Aggregate: aggregate}
}

func makeRehearsalCollectionRecord(evidence rehearsalCollectionEvidence) (rehearsalCollectionRecord, error) {
	payload, err := marshalPrivateJSON(evidence)
	if err != nil {
		return rehearsalCollectionRecord{}, err
	}
	defer clear(payload)
	return rehearsalCollectionRecord{Evidence: evidence, SHA256: sha256Bytes(payload)}, nil
}

func equalRehearsalCollectionEvidence(first, second rehearsalCollectionEvidence) bool {
	firstPayload, firstErr := marshalPrivateJSON(first)
	secondPayload, secondErr := marshalPrivateJSON(second)
	defer clear(firstPayload)
	defer clear(secondPayload)
	return firstErr == nil && secondErr == nil && bytes.Equal(firstPayload, secondPayload)
}

// SealRehearsalGate validates and binds three receipts without constructing a
// remote transport. It independently revalidates the current private spec and
// the executable that will later be admitted to final capture.
func SealRehearsalGate(options SealRehearsalGateOptions) (RehearsalGateReport, error) {
	if os.Geteuid() != 0 {
		return RehearsalGateReport{}, errors.New("rehearsal gate sealing requires root")
	}
	return sealRehearsalGate(options, 0, currentExecutableIdentity, func() time.Time { return time.Now().UTC() })
}

func sealRehearsalGate(options SealRehearsalGateOptions, expectedUID uint32, identity identityProvider, now func() time.Time) (RehearsalGateReport, error) {
	if len(options.ReceiptPaths) != rehearsalGateReceiptCount {
		return RehearsalGateReport{}, errors.New("rehearsal gate requires exactly three receipt paths")
	}
	if identity == nil {
		return RehearsalGateReport{}, errors.New("rehearsal gate executable identity provider is unavailable")
	}
	currentIdentity, err := identity()
	if err != nil || !validExecutableIdentity(currentIdentity) {
		return RehearsalGateReport{}, errors.New("rehearsal gate executable identity is invalid")
	}
	loaded, err := loadSpec(options.SpecPath, expectedUID)
	if err != nil {
		return RehearsalGateReport{}, err
	}
	if err := verifyPrivateLocalInputs(loaded.value.LocalFiles, expectedUID); err != nil {
		return RehearsalGateReport{}, err
	}
	if err := verifySSHTransportInputs(loaded.value.SSHTransport, expectedUID); err != nil {
		return RehearsalGateReport{}, err
	}
	gateParentFD, err := preparePrivateNoReplaceOutput(options.GateOutput, "rehearsal gate", expectedUID)
	if err != nil {
		return RehearsalGateReport{}, err
	}
	defer unix.Close(gateParentFD)
	seenPaths := make(map[string]bool, rehearsalGateReceiptCount+1)
	seenPaths[options.GateOutput] = true
	type verifiedReceipt struct {
		value  rehearsalReceipt
		digest string
	}
	receipts := make([]verifiedReceipt, 0, rehearsalGateReceiptCount)
	seenIDs := make(map[string]bool, rehearsalGateReceiptCount)
	seenDigests := make(map[string]bool, rehearsalGateReceiptCount)
	for _, receiptPath := range options.ReceiptPaths {
		if seenPaths[receiptPath] {
			return RehearsalGateReport{}, errors.New("rehearsal receipt paths must be absolute and unique")
		}
		seenPaths[receiptPath] = true
		var receipt rehearsalReceipt
		_, digest, err := readPrivateCanonicalJSON(receiptPath, "rehearsal receipt", maxRehearsalMetadataBytes, expectedUID, &receipt)
		if err != nil {
			return RehearsalGateReport{}, err
		}
		if err := validateRehearsalReceipt(receipt); err != nil {
			return RehearsalGateReport{}, err
		}
		if seenIDs[receipt.RehearsalID] || seenDigests[digest] {
			return RehearsalGateReport{}, errors.New("rehearsal receipt IDs and file digests must be unique")
		}
		seenIDs[receipt.RehearsalID], seenDigests[digest] = true, true
		receipts = append(receipts, verifiedReceipt{value: receipt, digest: digest})
	}
	first := receipts[0].value
	for _, receipt := range receipts {
		if receipt.value.SpecSHA256 != loaded.digest || receipt.value.Executable != currentIdentity || receipt.value.SourceCount != len(loaded.value.Sources) {
			return RehearsalGateReport{}, errors.New("rehearsal receipt does not match the current private spec and executable")
		}
		if err := validateRehearsalReceiptAgainstSpec(receipt.value, loaded.value); err != nil {
			return RehearsalGateReport{}, err
		}
		if receipt.value.SpecSHA256 != first.SpecSHA256 || receipt.value.Executable != first.Executable || receipt.value.SourceCount != first.SourceCount {
			return RehearsalGateReport{}, errors.New("rehearsal receipts do not bind one spec, executable, revision, and source count")
		}
	}
	sort.Slice(receipts, func(i, j int) bool {
		if receipts[i].value.StartedAt.Equal(receipts[j].value.StartedAt) {
			return receipts[i].value.RehearsalID < receipts[j].value.RehearsalID
		}
		return receipts[i].value.StartedAt.Before(receipts[j].value.StartedAt)
	})
	for index := 1; index < len(receipts); index++ {
		if receipts[index].value.StartedAt.Before(receipts[index-1].value.CompletedAt) {
			return RehearsalGateReport{}, errors.New("rehearsal receipt intervals overlap")
		}
	}
	relation := "identical"
	firstEvidenceDigest := receipts[0].value.Collections[0].SHA256
	for _, receipt := range receipts[1:] {
		if receipt.value.Collections[0].SHA256 != firstEvidenceDigest {
			relation = "varied"
		}
	}
	sealedAt := now().UTC()
	if sealedAt.IsZero() || sealedAt.Before(receipts[len(receipts)-1].value.CompletedAt) {
		return RehearsalGateReport{}, errors.New("rehearsal gate UTC seal time is invalid")
	}
	bindings := make([]rehearsalReceiptBinding, len(receipts))
	for index, receipt := range receipts {
		bindings[index] = rehearsalReceiptBinding{Receipt: receipt.value, ReceiptSHA256: receipt.digest}
	}
	gate := rehearsalGate{
		SchemaVersion: rehearsalGateSchemaVersion, Status: "sealed-three-rehearsal-gate",
		SpecSHA256: first.SpecSHA256, Executable: first.Executable, SourceCount: first.SourceCount,
		ReceiptCount: rehearsalGateReceiptCount, CollectionCount: rehearsalCollectionCount,
		CrossRunState: relation, Receipts: bindings, SealedAt: sealedAt,
	}
	if err := validateRehearsalGate(gate); err != nil {
		return RehearsalGateReport{}, err
	}
	reloaded, err := loadSpec(options.SpecPath, expectedUID)
	if err != nil || reloaded.digest != loaded.digest {
		return RehearsalGateReport{}, errors.New("private capture spec drifted during rehearsal gate sealing")
	}
	if err := verifyPrivateLocalInputs(reloaded.value.LocalFiles, expectedUID); err != nil {
		return RehearsalGateReport{}, errors.New("private local capture input drifted during rehearsal gate sealing")
	}
	if err := verifySSHTransportInputs(reloaded.value.SSHTransport, expectedUID); err != nil {
		return RehearsalGateReport{}, errors.New("private SSH transport binding drifted during rehearsal gate sealing")
	}
	endingIdentity, err := identity()
	if err != nil || endingIdentity != currentIdentity {
		return RehearsalGateReport{}, errors.New("executable identity drifted during rehearsal gate sealing")
	}
	payload, err := marshalPrivateJSON(gate)
	if err != nil {
		return RehearsalGateReport{}, errors.New("encode private rehearsal gate")
	}
	defer clear(payload)
	digest := sha256Bytes(payload)
	if err := writePrivatePayloadNoReplaceAt(gateParentFD, options.GateOutput, payload, "rehearsal gate", expectedUID); err != nil {
		return RehearsalGateReport{}, err
	}
	return RehearsalGateReport{
		SchemaVersion: 1, Status: gate.Status, SpecSHA256: gate.SpecSHA256, GateSHA256: digest,
		SourceCount: gate.SourceCount, ReceiptCount: gate.ReceiptCount,
		CrossRunState: relation, CompletedAt: sealedAt,
	}, nil
}

func validateRehearsalReceipt(receipt rehearsalReceipt) error {
	if receipt.SchemaVersion != rehearsalReceiptSchemaVersion || receipt.Status != "complete-read-only-rehearsal" ||
		!validCaptureID(receipt.RehearsalID) || !receipt.WritersQuiesced || receipt.ConfirmationClass != "REHEARSAL-WRITERS-QUIESCED" ||
		!sha256Pattern.MatchString(receipt.SpecSHA256) || !validExecutableIdentity(receipt.Executable) ||
		receipt.SourceCount < 1 || receipt.SourceCount > 2048 || receipt.CollectionCount != rehearsalCollectionCount ||
		len(receipt.Collections) != rehearsalCollectionCount || receipt.StartedAt.IsZero() || !receipt.CompletedAt.After(receipt.StartedAt) {
		return errors.New("private rehearsal receipt contract is invalid")
	}
	for _, collection := range receipt.Collections {
		if len(collection.Evidence.Sources) != receipt.SourceCount || !validAnonymousCollectionEvidence(collection.Evidence) {
			return errors.New("private rehearsal receipt collection evidence is invalid")
		}
		recomputed, err := makeRehearsalCollectionRecord(collection.Evidence)
		if err != nil || recomputed.SHA256 != collection.SHA256 {
			return errors.New("private rehearsal receipt collection digest is invalid")
		}
	}
	if receipt.Collections[0].SHA256 != receipt.Collections[1].SHA256 ||
		!equalRehearsalCollectionEvidence(receipt.Collections[0].Evidence, receipt.Collections[1].Evidence) {
		return errors.New("private rehearsal receipt collections do not converge")
	}
	return nil
}

func validAnonymousCollectionEvidence(evidence rehearsalCollectionEvidence) bool {
	inventories := make([]inventory, len(evidence.Sources))
	for index, source := range evidence.Sources {
		if !validSummary(source.Summary) || !sha256Pattern.MatchString(source.ArchiveSHA256) ||
			!sha256Pattern.MatchString(source.EvidenceSHA256) || !sha256Pattern.MatchString(source.ExclusionSHA) {
			return false
		}
		inventories[index].summary = source.Summary
	}
	if evidence.OAuth.Files < 0 || evidence.OAuth.Bytes < 0 || !sha256Pattern.MatchString(evidence.OAuth.SHA256) || !validSummary(evidence.Aggregate) {
		return false
	}
	aggregate, err := aggregateSummaries(inventories)
	return err == nil && aggregate == evidence.Aggregate
}

func validSummary(summary Summary) bool {
	return summary.Files >= 0 && summary.Directories >= 0 && summary.Symlinks >= 0 && summary.Bytes >= 0 &&
		summary.Files < 1<<62 && summary.Directories < 1<<62 && summary.Symlinks < 1<<62 && summary.Bytes < 1<<62 &&
		sha256Pattern.MatchString(summary.SHA256)
}

func validateRehearsalReceiptAgainstSpec(receipt rehearsalReceipt, spec Spec) error {
	if receipt.SourceCount != len(spec.Sources) {
		return errors.New("private rehearsal receipt source count does not match the current spec")
	}
	for _, collection := range receipt.Collections {
		if len(collection.Evidence.Sources) != len(spec.Sources) ||
			collection.Evidence.Aggregate.Files > spec.Limits.MaxTotalFiles || collection.Evidence.Aggregate.Bytes > spec.Limits.MaxTotalBytes ||
			collection.Evidence.OAuth.Files > spec.OAuthEvidence.MaxFiles || collection.Evidence.OAuth.Bytes > spec.OAuthEvidence.MaxBytes {
			return errors.New("private rehearsal receipt evidence exceeds the current spec")
		}
		for index, evidence := range collection.Evidence.Sources {
			entries := evidence.Summary.Files
			if evidence.Summary.Directories > (1<<62)-entries {
				return errors.New("private rehearsal receipt source entry count overflows")
			}
			entries += evidence.Summary.Directories
			if evidence.Summary.Symlinks > (1<<62)-entries {
				return errors.New("private rehearsal receipt source entry count overflows")
			}
			entries += evidence.Summary.Symlinks
			if entries > spec.Sources[index].MaxFiles || evidence.Summary.Bytes > spec.Sources[index].MaxBytes {
				return errors.New("private rehearsal receipt source evidence exceeds the current spec")
			}
		}
	}
	return nil
}

func validateRehearsalGateAgainstSpec(gate rehearsalGate, spec Spec) error {
	if gate.SourceCount != len(spec.Sources) {
		return errors.New("private rehearsal gate source count does not match the current spec")
	}
	for _, binding := range gate.Receipts {
		if err := validateRehearsalReceiptAgainstSpec(binding.Receipt, spec); err != nil {
			return err
		}
	}
	return nil
}

func validateRehearsalGate(gate rehearsalGate) error {
	if gate.SchemaVersion != rehearsalGateSchemaVersion || gate.Status != "sealed-three-rehearsal-gate" ||
		!sha256Pattern.MatchString(gate.SpecSHA256) || !validExecutableIdentity(gate.Executable) ||
		gate.SourceCount < 1 || gate.SourceCount > 2048 || gate.ReceiptCount != rehearsalGateReceiptCount ||
		gate.CollectionCount != rehearsalCollectionCount || len(gate.Receipts) != rehearsalGateReceiptCount ||
		(gate.CrossRunState != "identical" && gate.CrossRunState != "varied") || gate.SealedAt.IsZero() {
		return errors.New("private rehearsal gate contract is invalid")
	}
	seenIDs := make(map[string]bool, len(gate.Receipts))
	seenDigests := make(map[string]bool, len(gate.Receipts))
	recomputedState := "identical"
	firstEvidenceDigest := ""
	for index, binding := range gate.Receipts {
		receipt := binding.Receipt
		if validateRehearsalReceipt(receipt) != nil || !sha256Pattern.MatchString(binding.ReceiptSHA256) ||
			seenIDs[receipt.RehearsalID] || seenDigests[binding.ReceiptSHA256] || gate.SealedAt.Before(receipt.CompletedAt) ||
			receipt.SpecSHA256 != gate.SpecSHA256 || receipt.Executable != gate.Executable || receipt.SourceCount != gate.SourceCount {
			return errors.New("private rehearsal gate receipt binding is invalid")
		}
		payload, err := marshalPrivateJSON(receipt)
		if err != nil || sha256Bytes(payload) != binding.ReceiptSHA256 {
			clear(payload)
			return errors.New("private rehearsal gate receipt digest is invalid")
		}
		clear(payload)
		if index > 0 && receipt.StartedAt.Before(gate.Receipts[index-1].Receipt.CompletedAt) {
			return errors.New("private rehearsal gate intervals overlap or are unsorted")
		}
		if index == 0 {
			firstEvidenceDigest = receipt.Collections[0].SHA256
		} else if receipt.Collections[0].SHA256 != firstEvidenceDigest {
			recomputedState = "varied"
		}
		seenIDs[receipt.RehearsalID], seenDigests[binding.ReceiptSHA256] = true, true
	}
	if gate.CrossRunState != recomputedState {
		return errors.New("private rehearsal gate cross-run state is invalid")
	}
	return nil
}

func readVerifiedRehearsalGate(filename string, expectedUID uint32) (verifiedRehearsalGate, error) {
	var gate rehearsalGate
	payload, digest, err := readPrivateCanonicalJSON(filename, "rehearsal gate", maxRehearsalMetadataBytes, expectedUID, &gate)
	if err != nil {
		return verifiedRehearsalGate{}, err
	}
	if err := validateRehearsalGate(gate); err != nil {
		clear(payload)
		return verifiedRehearsalGate{}, err
	}
	return verifiedRehearsalGate{value: gate, payload: payload, digest: digest}, nil
}

func readPrivateCanonicalJSON(filename, label string, maximum int64, expectedUID uint32, destination any) ([]byte, string, error) {
	if err := validateAbsoluteFilePath(filename, label); err != nil || maximum < 1 {
		return nil, "", fmt.Errorf("private %s path or size bound is invalid", label)
	}
	parentFD, _, err := openPrivateRoot(filepath.Dir(filename), expectedUID)
	if err != nil {
		return nil, "", fmt.Errorf("private %s parent must be a real 0700 directory", label)
	}
	defer unix.Close(parentFD)
	leaf := filepath.Base(filename)
	if !safePrivateLeaf(leaf) {
		return nil, "", fmt.Errorf("private %s filename is unsafe", label)
	}
	fd, err := unix.Openat2(parentFD, leaf, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: localResolveFlags})
	if err != nil {
		return nil, "", fmt.Errorf("open private %s", label)
	}
	file := os.NewFile(uintptr(fd), "private-rehearsal-metadata")
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(before.Mode).Perm() != 0o600 ||
		before.Uid != expectedUID || before.Gid != expectedUID || before.Nlink != 1 || before.Size < 1 || before.Size > maximum {
		return nil, "", fmt.Errorf("private %s is unsafe", label)
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(payload)) != before.Size {
		clear(payload)
		return nil, "", fmt.Errorf("private %s is unreadable", label)
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !stableFileStat(before, after) {
		clear(payload)
		return nil, "", fmt.Errorf("private %s changed while it was read", label)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		clear(payload)
		return nil, "", fmt.Errorf("private %s is not strict JSON", label)
	}
	canonical, err := marshalPrivateJSON(destination)
	if err != nil || !bytes.Equal(payload, canonical) {
		clear(payload)
		clear(canonical)
		return nil, "", fmt.Errorf("private %s is not canonical JSON", label)
	}
	clear(canonical)
	if err := unix.Fsync(fd); err != nil {
		clear(payload)
		return nil, "", fmt.Errorf("sync private %s during durable readback", label)
	}
	if err := unix.Fsync(parentFD); err != nil {
		clear(payload)
		return nil, "", fmt.Errorf("sync private %s parent during durable readback", label)
	}
	return payload, sha256Bytes(payload), nil
}

func preparePrivateNoReplaceOutput(filename, label string, expectedUID uint32) (int, error) {
	if err := validateAbsoluteFilePath(filename, label+" output"); err != nil {
		return -1, err
	}
	leaf := filepath.Base(filename)
	if !safePrivateLeaf(leaf) {
		return -1, fmt.Errorf("%s output filename is unsafe", label)
	}
	parentFD, _, err := openPrivateRoot(filepath.Dir(filename), expectedUID)
	if err != nil {
		return -1, fmt.Errorf("%s output parent must be a real private 0700 directory", label)
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, leaf, &stat, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		unix.Close(parentFD)
		return -1, fmt.Errorf("%s output already exists", label)
	} else if !errors.Is(err, unix.ENOENT) {
		unix.Close(parentFD)
		return -1, fmt.Errorf("inspect %s output", label)
	}
	return parentFD, nil
}

// writePrivatePayloadNoReplaceAt keeps admission, any caller-held advisory
// lock, temporary-file creation, and publication on one directory descriptor.
// The path is re-resolved immediately before and after publication only to
// prove that it still names that same private directory inode.
func writePrivatePayloadNoReplaceAt(parentFD int, filename string, payload []byte, label string, expectedUID uint32) error {
	if len(payload) < 1 || len(payload) > maxRehearsalMetadataBytes {
		return fmt.Errorf("private %s payload is invalid", label)
	}
	if err := verifyPrivateOutputParentIdentity(parentFD, filename, label, expectedUID); err != nil {
		return err
	}
	temporaryLeaf, temporaryFD, err := createPrivatePartialAt(parentFD)
	if err != nil {
		return fmt.Errorf("create private %s partial", label)
	}
	published := false
	defer func() {
		if !published {
			_ = unix.Unlinkat(parentFD, temporaryLeaf, 0)
			_ = unix.Fsync(parentFD)
		}
	}()
	temporary := os.NewFile(uintptr(temporaryFD), "private-rehearsal-partial")
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure private %s partial", label)
	}
	if written, err := temporary.Write(payload); err != nil || written != len(payload) {
		temporary.Close()
		return fmt.Errorf("write private %s partial", label)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync private %s partial", label)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close private %s partial", label)
	}
	if err := unix.Fsync(parentFD); err != nil {
		return fmt.Errorf("sync private %s parent before publication", label)
	}
	if err := verifyPrivateOutputParentIdentity(parentFD, filename, label, expectedUID); err != nil {
		return err
	}
	if err := unix.Renameat2(parentFD, temporaryLeaf, parentFD, filepath.Base(filename), unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("publish private %s without replacement", label)
	}
	published = true
	if err := unix.Fsync(parentFD); err != nil {
		return fmt.Errorf("sync private %s parent after publication", label)
	}
	if err := verifyPrivateOutputParentIdentity(parentFD, filename, label, expectedUID); err != nil {
		return err
	}
	return nil
}

func verifyPrivateOutputParentIdentity(parentFD int, filename, label string, expectedUID uint32) error {
	if err := validateAbsoluteFilePath(filename, label+" output"); err != nil || !safePrivateLeaf(filepath.Base(filename)) {
		return fmt.Errorf("private %s output path is invalid", label)
	}
	var held unix.Stat_t
	if err := unix.Fstat(parentFD, &held); err != nil || held.Mode&unix.S_IFMT != unix.S_IFDIR || held.Uid != expectedUID || held.Gid != expectedUID ||
		os.FileMode(held.Mode).Perm() != 0o700 {
		return fmt.Errorf("private %s output parent descriptor is unsafe", label)
	}
	resolvedFD, resolved, err := openPrivateRoot(filepath.Dir(filename), expectedUID)
	if err != nil {
		return fmt.Errorf("private %s output parent path drifted", label)
	}
	defer unix.Close(resolvedFD)
	if held.Dev != resolved.Dev || held.Ino != resolved.Ino || held.Mode != resolved.Mode || held.Uid != resolved.Uid || held.Gid != resolved.Gid {
		return fmt.Errorf("private %s output parent path drifted", label)
	}
	return nil
}

func sha256Bytes(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
