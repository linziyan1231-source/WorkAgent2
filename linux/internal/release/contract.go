package release

import (
	"errors"
	"fmt"
	"slices"
	"sort"
)

const maxConsumerContractPaths = 1024

// ConsumerContract is the canonical set of release files a configured channel
// can consume. Data and executable paths are deliberately distinct so an
// activation cannot turn an unreadable file into a latent command boundary.
type ConsumerContract struct {
	RequiredPaths           []string `json:"required_paths"`
	RequiredExecutablePaths []string `json:"required_executable_paths"`
}

func NewConsumerContract(requiredPaths, requiredExecutablePaths []string) (ConsumerContract, error) {
	contract := ConsumerContract{
		RequiredPaths:           append([]string{}, requiredPaths...),
		RequiredExecutablePaths: append([]string{}, requiredExecutablePaths...),
	}
	sort.Strings(contract.RequiredPaths)
	sort.Strings(contract.RequiredExecutablePaths)
	if err := contract.Validate(); err != nil {
		return ConsumerContract{}, err
	}
	return contract, nil
}

func (c ConsumerContract) Validate() error {
	// append([]string{}, nil...) yields a non-nil empty slice; only a
	// hand-built contract can still carry nil. Both lists may individually be
	// empty as long as the contract asserts at least one path.
	if c.RequiredPaths == nil || c.RequiredExecutablePaths == nil ||
		len(c.RequiredPaths)+len(c.RequiredExecutablePaths) == 0 ||
		len(c.RequiredPaths)+len(c.RequiredExecutablePaths) > maxConsumerContractPaths {
		return errors.New("release consumer contract is missing or too large")
	}
	if !sort.StringsAreSorted(c.RequiredPaths) || !sort.StringsAreSorted(c.RequiredExecutablePaths) {
		return errors.New("release consumer contract paths are not canonical")
	}
	seen := make(map[string]string, len(c.RequiredPaths)+len(c.RequiredExecutablePaths))
	for kind, paths := range map[string][]string{"data": c.RequiredPaths, "executable": c.RequiredExecutablePaths} {
		for _, path := range paths {
			if err := validRelativePath(path); err != nil {
				return fmt.Errorf("release consumer %s path %q is invalid: %w", kind, path, err)
			}
			if previous, exists := seen[path]; exists {
				return fmt.Errorf("release consumer path %q is duplicated across %s and %s requirements", path, previous, kind)
			}
			seen[path] = kind
		}
	}
	return nil
}

func (c ConsumerContract) Equal(other ConsumerContract) bool {
	return slices.Equal(c.RequiredPaths, other.RequiredPaths) &&
		slices.Equal(c.RequiredExecutablePaths, other.RequiredExecutablePaths)
}

func ValidateManifestConsumerContract(manifest Manifest, contract ConsumerContract) error {
	if err := contract.Validate(); err != nil {
		return err
	}
	modes := make(map[string]string, len(manifest.Files))
	for _, file := range manifest.Files {
		modes[file.Path] = file.Mode
	}
	for _, path := range contract.RequiredPaths {
		if modes[path] != "0444" {
			return fmt.Errorf("required release data file %q is missing or not canonically non-executable", path)
		}
	}
	for _, path := range contract.RequiredExecutablePaths {
		if modes[path] != "0555" {
			return fmt.Errorf("required release executable %q is missing or not canonically executable", path)
		}
	}
	return nil
}
