package userhost

import (
	"errors"
	"fmt"
	"os"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/modelbootstrap"
)

const (
	kimiModelDefaultsMarkerPath    = "config/kimi-model-defaults-v1.applied"
	kimiModelDefaultsMarkerContent = "default_model=" + modelbootstrap.DefaultKimiModel +
		"\nefforts=low,high,max\ndefaults=kimi-for-coding:high,kimi-for-coding-highspeed:high,kimi-k3:low\n"
)

// applyKimiModelDefaults upgrades only the key-free applied model state. The
// caller rewrites the managed CLI configuration from the already-loaded key
// bundle, so neither Codex nor Kimi credentials are read again or rotated.
func (h *Host) applyKimiModelDefaults() (modelbootstrap.State, bool, error) {
	marker, err := h.dataRoot.ReadFile(kimiModelDefaultsMarkerPath, 4096)
	if err == nil {
		if string(marker) != kimiModelDefaultsMarkerContent {
			return modelbootstrap.State{}, false, errors.New("Kimi model defaults marker has unexpected content")
		}
		pending, pendingErr := h.readPendingModelBundle()
		if pendingErr == nil {
			pending.Zero()
			return modelbootstrap.State{}, false, nil
		}
		if !errors.Is(pendingErr, os.ErrNotExist) {
			return modelbootstrap.State{}, false, fmt.Errorf("inspect pending model bootstrap after Kimi defaults migration: %w", pendingErr)
		}
		state, stateErr := h.readAppliedModelState()
		if stateErr != nil {
			return modelbootstrap.State{}, false, fmt.Errorf("verify applied model bootstrap after Kimi defaults migration: %w", stateErr)
		}
		if state.ValidateManagedForTenant(h.cfg.TenantID) != nil {
			return modelbootstrap.State{}, false, errors.New("Kimi model defaults marker conflicts with the applied bootstrap state")
		}
		return state, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return modelbootstrap.State{}, false, fmt.Errorf("read Kimi model defaults marker: %w", err)
	}

	pending, pendingErr := h.readPendingModelBundle()
	if pendingErr == nil {
		pending.Zero()
		return modelbootstrap.State{}, false, nil
	}
	if !errors.Is(pendingErr, os.ErrNotExist) {
		return modelbootstrap.State{}, false, fmt.Errorf("inspect pending model bootstrap before Kimi defaults migration: %w", pendingErr)
	}

	state, err := h.readAppliedModelState()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return modelbootstrap.State{}, false, errors.New("model bootstrap must be applied without a pending operation")
		}
		return modelbootstrap.State{}, false, fmt.Errorf("read applied model bootstrap for Kimi defaults migration: %w", err)
	}
	updated, _, err := state.WithManagedKimiDefaults(h.cfg.TenantID)
	if err != nil {
		return modelbootstrap.State{}, false, err
	}
	payload, err := encodeStrictJSON(updated)
	if err != nil {
		return modelbootstrap.State{}, false, err
	}
	defer clear(payload)
	if err := h.dataRoot.WriteFileAtomic(modelBootstrapMarkerPath, payload, 0o600); err != nil {
		return modelbootstrap.State{}, false, fmt.Errorf("write updated Kimi model bootstrap marker: %w", err)
	}
	verified, err := h.readAppliedModelState()
	if err != nil || !verified.Equal(updated) {
		return modelbootstrap.State{}, false, fmt.Errorf("verify updated Kimi model bootstrap marker: %w", err)
	}
	if pending, err := h.readPendingModelBundle(); err == nil {
		pending.Zero()
		return modelbootstrap.State{}, false, errors.New("model bootstrap became pending during Kimi defaults migration")
	} else if !errors.Is(err, os.ErrNotExist) {
		return modelbootstrap.State{}, false, fmt.Errorf("verify pending model bootstrap after Kimi defaults migration: %w", err)
	}
	if err := h.dataRoot.WriteFileAtomic(kimiModelDefaultsMarkerPath, []byte(kimiModelDefaultsMarkerContent), 0o600); err != nil {
		return modelbootstrap.State{}, false, fmt.Errorf("write Kimi model defaults marker: %w", err)
	}
	marker, err = h.dataRoot.ReadFile(kimiModelDefaultsMarkerPath, 4096)
	if err != nil || string(marker) != kimiModelDefaultsMarkerContent {
		return modelbootstrap.State{}, false, fmt.Errorf("verify Kimi model defaults marker: %w", err)
	}
	return updated, true, nil
}
