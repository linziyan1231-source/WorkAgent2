package userhost

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"

	"aionuiportal/internal/modelbootstrap"
)

const (
	codexModelDefaultsMarkerName    = "codex-model-defaults-v1.applied"
	codexModelDefaultsMarkerContent = "model=" + modelbootstrap.DefaultCodexModel + "\nmodel_reasoning_effort=" + modelbootstrap.DefaultCodexReasoningEffort + "\n"
)

var codexModelDefaultsAssignment = regexp.MustCompile(`^\s*(?:["']?(model_reasoning_effort|model)["']?)\s*=`)

func applyCodexModelDefaults(dataRoot string, dirs privateDirs) (bool, error) {
	markerPath := filepath.Join(dirs.Config, codexModelDefaultsMarkerName)
	applied, err := markerHasContent(markerPath, codexModelDefaultsMarkerContent)
	if err != nil || applied {
		return false, err
	}
	if _, err := modelbootstrap.UpdateAppliedCodexDefaultModel(dataRoot, modelbootstrap.DefaultCodexModel); err != nil {
		return false, fmt.Errorf("update applied model bootstrap default: %w", err)
	}
	configPath := filepath.Join(dirs.Config, "codex", "config.toml")
	managed := []string{
		"model = " + strconv.Quote(modelbootstrap.DefaultCodexModel),
		"model_reasoning_effort = " + strconv.Quote(modelbootstrap.DefaultCodexReasoningEffort),
		"",
	}
	if err := rewriteCodexConfig(configPath, codexModelDefaultsAssignment, managed); err != nil {
		return false, fmt.Errorf("set Codex model defaults: %w", err)
	}
	if err := writePrivateFileAtomic(markerPath, []byte(codexModelDefaultsMarkerContent)); err != nil {
		return false, fmt.Errorf("write Codex model defaults marker: %w", err)
	}
	return true, nil
}
