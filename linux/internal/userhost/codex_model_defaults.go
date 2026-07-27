package userhost

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/modelbootstrap"
)

const (
	codexModelDefaultsMarkerPath    = "config/codex-model-defaults-v1.applied"
	codexModelDefaultsMarkerContent = "model=" + modelbootstrap.DefaultCodexModel +
		"\nmodel_reasoning_effort=" + modelbootstrap.DefaultCodexReasoningEffort + "\n"
)

var codexModelDefaultsAssignment = regexp.MustCompile(`^\s*(?:["']?(model_reasoning_effort|model)["']?)\s*=`)

// applyCodexModelDefaults migrates an already-applied bootstrap state and the
// two managed Codex defaults without reading or rewriting auth.json. A pending
// bootstrap owns the same state and is therefore left for the normal bootstrap
// path; a conflicting or partially staged operation fails closed.
func (h *Host) applyCodexModelDefaults() (modelbootstrap.State, bool, error) {
	marker, err := h.dataRoot.ReadFile(codexModelDefaultsMarkerPath, 4096)
	if err == nil {
		if string(marker) != codexModelDefaultsMarkerContent {
			return modelbootstrap.State{}, false, errors.New("Codex model defaults marker has unexpected content")
		}
		pending, pendingErr := h.readPendingModelBundle()
		if pendingErr == nil {
			pending.Zero()
			return modelbootstrap.State{}, false, nil
		}
		if !errors.Is(pendingErr, os.ErrNotExist) {
			return modelbootstrap.State{}, false, fmt.Errorf("inspect pending model bootstrap before Codex defaults migration: %w", pendingErr)
		}
		state, stateErr := h.readAppliedModelState()
		if stateErr != nil {
			return modelbootstrap.State{}, false, fmt.Errorf("verify applied model bootstrap after Codex defaults migration: %w", stateErr)
		}
		if state.CodexDefaultModel != modelbootstrap.DefaultCodexModel {
			return modelbootstrap.State{}, false, errors.New("Codex model defaults marker conflicts with the applied bootstrap state")
		}
		return state, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return modelbootstrap.State{}, false, fmt.Errorf("read Codex model defaults marker: %w", err)
	}

	pending, pendingErr := h.readPendingModelBundle()
	if pendingErr == nil {
		pending.Zero()
		return modelbootstrap.State{}, false, nil
	}
	if !errors.Is(pendingErr, os.ErrNotExist) {
		return modelbootstrap.State{}, false, fmt.Errorf("inspect pending model bootstrap before Codex defaults migration: %w", pendingErr)
	}

	state, err := h.readAppliedModelState()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return modelbootstrap.State{}, false, errors.New("model bootstrap must be applied without a pending operation")
		}
		return modelbootstrap.State{}, false, fmt.Errorf("read applied model bootstrap for Codex defaults migration: %w", err)
	}
	updated, _, err := state.WithCodexDefaultModel(h.cfg.TenantID, modelbootstrap.DefaultCodexModel)
	if err != nil {
		return modelbootstrap.State{}, false, err
	}
	statePayload, err := encodeStrictJSON(updated)
	if err != nil {
		return modelbootstrap.State{}, false, err
	}
	defer clear(statePayload)
	if err := h.dataRoot.WriteFileAtomic(modelBootstrapMarkerPath, statePayload, 0o600); err != nil {
		return modelbootstrap.State{}, false, fmt.Errorf("write updated applied model bootstrap marker: %w", err)
	}
	verified, err := h.readAppliedModelState()
	if err != nil {
		return modelbootstrap.State{}, false, fmt.Errorf("verify updated applied model bootstrap marker: %w", err)
	}
	if !verified.Equal(updated) {
		return modelbootstrap.State{}, false, errors.New("updated applied model bootstrap marker did not persist exactly")
	}
	if err := h.rewriteCodexModelDefaults(); err != nil {
		return modelbootstrap.State{}, false, err
	}
	if pending, err := h.readPendingModelBundle(); err == nil {
		pending.Zero()
		return modelbootstrap.State{}, false, errors.New("model bootstrap became pending during Codex defaults migration")
	} else if !errors.Is(err, os.ErrNotExist) {
		return modelbootstrap.State{}, false, fmt.Errorf("verify pending model bootstrap after Codex defaults migration: %w", err)
	}
	if err := h.dataRoot.WriteFileAtomic(codexModelDefaultsMarkerPath, []byte(codexModelDefaultsMarkerContent), 0o600); err != nil {
		return modelbootstrap.State{}, false, fmt.Errorf("write Codex model defaults marker: %w", err)
	}
	marker, err = h.dataRoot.ReadFile(codexModelDefaultsMarkerPath, 4096)
	if err != nil {
		return modelbootstrap.State{}, false, fmt.Errorf("verify Codex model defaults marker: %w", err)
	}
	if string(marker) != codexModelDefaultsMarkerContent {
		return modelbootstrap.State{}, false, errors.New("Codex model defaults marker did not persist exactly")
	}
	return updated, true, nil
}

func (h *Host) rewriteCodexModelDefaults() error {
	existing, err := h.dataRoot.ReadFile(codexConfigPath, maxModelConfigBytes)
	if err != nil {
		return fmt.Errorf("read Codex configuration for defaults migration: %w", err)
	}
	defer clear(existing)
	preserved, err := removeTopLevelAssignments(string(existing), codexModelDefaultsAssignment)
	if err != nil {
		return fmt.Errorf("rewrite Codex model defaults: %w", err)
	}
	managed := []string{
		"model = " + strconv.Quote(modelbootstrap.DefaultCodexModel),
		"model_reasoning_effort = " + strconv.Quote(modelbootstrap.DefaultCodexReasoningEffort),
		"",
	}
	content := strings.Join(managed, "\n") + strings.TrimLeft(preserved, "\n")
	content = strings.TrimRight(content, "\n") + "\n"
	if err := h.dataRoot.WriteFileAtomic(codexConfigPath, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write Codex model defaults: %w", err)
	}
	verified, err := h.dataRoot.ReadFile(codexConfigPath, maxModelConfigBytes)
	if err != nil {
		return fmt.Errorf("verify Codex model defaults: %w", err)
	}
	if !bytes.Equal(verified, []byte(content)) {
		return errors.New("Codex model defaults did not persist exactly")
	}
	return nil
}
