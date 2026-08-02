package productconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Brand struct {
	SchemaVersion int     `json:"schema_version"`
	BrandID       string  `json:"brand_id"`
	CompanyName   string  `json:"company_name"`
	PlatformName  string  `json:"platform_name"`
	PrimaryColor  string  `json:"primary_color"`
	Assets        Assets  `json:"assets"`
	HelpURL       *string `json:"help_url"`
	SupportURL    *string `json:"support_url"`
	baseDirectory string
}

type Assets struct {
	Logo     string `json:"logo"`
	LogoDark string `json:"logo_dark"`
	Favicon  string `json:"favicon"`
	AppIcon  string `json:"app_icon"`
}

type Policy struct {
	SchemaVersion    int               `json:"schema_version"`
	PolicyID         string            `json:"policy_id"`
	DefaultAction    string            `json:"default_action"`
	Models           []Model           `json:"models"`
	Aliases          map[string]string `json:"aliases"`
	Pricing          map[string]Price  `json:"pricing"`
	Quotas           map[string]Quota  `json:"quotas"`
	ApprovalRequired bool              `json:"approval_required"`
}

type Model struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Provider    string `json:"provider"`
	Enabled     bool   `json:"enabled"`
	Default     bool   `json:"default,omitempty"`
}

type Price struct {
	InputPerMillion  string `json:"input_per_million"`
	OutputPerMillion string `json:"output_per_million"`
	Currency         string `json:"currency"`
}

type Quota struct {
	RequestsPerMinute int    `json:"requests_per_minute"`
	DailyRequests     int    `json:"daily_requests"`
	WeeklyRequests    int    `json:"weekly_requests"`
	DailyUSD          string `json:"daily_usd"`
	WeeklyUSD         string `json:"weekly_usd"`
}

var (
	identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	colorPattern      = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)
	moneyPattern      = regexp.MustCompile(`^(0|[1-9][0-9]{0,11})(\.[0-9]{1,6})?$`)
)

func LoadBrand(path string) (Brand, error) {
	var value Brand
	if err := loadStrict(path, &value); err != nil {
		return Brand{}, err
	}
	value.baseDirectory = filepath.Dir(path)
	if err := value.Validate(); err != nil {
		return Brand{}, fmt.Errorf("validate brand configuration: %w", err)
	}
	return value, nil
}

func LoadPolicy(path string) (Policy, error) {
	var value Policy
	if err := loadStrict(path, &value); err != nil {
		return Policy{}, err
	}
	if err := value.Validate(); err != nil {
		return Policy{}, fmt.Errorf("validate policy configuration: %w", err)
	}
	return value, nil
}

func loadStrict(path string, destination any) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("product configuration path must be clean and absolute")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1024*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("product configuration must contain one JSON value")
	}
	return nil
}

func (b Brand) Validate() error {
	if b.SchemaVersion != 1 || b.BrandID != "workagent" {
		return errors.New("brand schema or identifier is invalid")
	}
	if b.CompanyName != "WorkAgent" || b.PlatformName != "WorkAgent2" {
		return errors.New("brand names do not match the approved WorkAgent2 baseline")
	}
	if !colorPattern.MatchString(b.PrimaryColor) {
		return errors.New("primary_color must be a six-digit hexadecimal color")
	}
	for name, path := range map[string]string{"logo": b.Assets.Logo, "logo_dark": b.Assets.LogoDark, "favicon": b.Assets.Favicon, "app_icon": b.Assets.AppIcon} {
		if err := validAssetPath(path); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if b.baseDirectory != "" {
			info, err := os.Lstat(filepath.Join(b.baseDirectory, filepath.FromSlash(path)))
			if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 2*1024*1024 {
				return fmt.Errorf("%s is missing or unsafe", name)
			}
		}
	}
	return nil
}

func (b Brand) AssetPath(name string) (string, bool) {
	assets := map[string]string{"logo": b.Assets.Logo, "logo-dark": b.Assets.LogoDark, "favicon": b.Assets.Favicon, "app-icon": b.Assets.AppIcon}
	relative, ok := assets[name]
	if !ok || b.baseDirectory == "" {
		return "", false
	}
	return filepath.Join(b.baseDirectory, filepath.FromSlash(relative)), true
}

func (p Policy) Validate() error {
	if p.SchemaVersion != 1 || !identifierPattern.MatchString(p.PolicyID) {
		return errors.New("policy schema or identifier is invalid")
	}
	if p.DefaultAction != "deny" {
		return errors.New("policy.default_action must be deny")
	}
	seen := make(map[string]struct{}, len(p.Models))
	providerDefaults := make(map[string]int)
	providerEnabled := make(map[string]int)
	for _, model := range p.Models {
		if !identifierPattern.MatchString(model.ID) || model.DisplayName == "" || !identifierPattern.MatchString(model.Provider) {
			return fmt.Errorf("model entry %q is invalid", model.ID)
		}
		if _, exists := seen[model.ID]; exists {
			return fmt.Errorf("duplicate model %q", model.ID)
		}
		seen[model.ID] = struct{}{}
		if model.Default && !model.Enabled {
			return fmt.Errorf("disabled model %q cannot be the provider default", model.ID)
		}
		if model.Enabled {
			providerEnabled[model.Provider]++
			if model.Default {
				providerDefaults[model.Provider]++
			}
		}
	}
	for provider := range providerEnabled {
		if providerDefaults[provider] != 1 {
			return fmt.Errorf("provider %q must have exactly one enabled default model", provider)
		}
	}
	for alias, target := range p.Aliases {
		if !identifierPattern.MatchString(alias) {
			return fmt.Errorf("model alias %q is invalid", alias)
		}
		if _, exists := seen[target]; !exists {
			return fmt.Errorf("model alias %q points to an unknown model", alias)
		}
		if _, collides := seen[alias]; collides {
			return fmt.Errorf("model alias %q collides with a model id", alias)
		}
	}
	for model, price := range p.Pricing {
		if _, exists := seen[model]; !exists {
			return fmt.Errorf("pricing references unknown model %q", model)
		}
		if !validMoney(price.InputPerMillion, true) || !validMoney(price.OutputPerMillion, true) || (price.Currency != "USD" && price.Currency != "CNY") {
			return fmt.Errorf("pricing for model %q is invalid", model)
		}
	}
	for model, quota := range p.Quotas {
		if _, exists := seen[model]; !exists || quota.RequestsPerMinute < 0 || quota.RequestsPerMinute > 100000 || quota.DailyRequests < 0 || quota.WeeklyRequests < 0 ||
			!validMoney(quota.DailyUSD, false) || !validMoney(quota.WeeklyUSD, false) {
			return fmt.Errorf("quota references invalid model %q", model)
		}
		daily, _ := new(big.Rat).SetString(quota.DailyUSD)
		weekly, _ := new(big.Rat).SetString(quota.WeeklyUSD)
		if weekly.Cmp(daily) < 0 {
			return fmt.Errorf("weekly quota for model %q is below its daily quota", model)
		}
	}
	return nil
}

func validMoney(value string, allowZero bool) bool {
	if !moneyPattern.MatchString(value) {
		return false
	}
	parsed, ok := new(big.Rat).SetString(value)
	if !ok || parsed.Sign() < 0 || (!allowZero && parsed.Sign() == 0) {
		return false
	}
	return parsed.Denom().BitLen() <= 32
}

func (p Policy) EnabledModels(provider string) []Model {
	result := make([]Model, 0)
	for _, model := range p.Models {
		if model.Enabled && model.Provider == provider {
			result = append(result, model)
		}
	}
	return result
}

func (p Policy) DefaultModel(provider string) (Model, bool) {
	for _, model := range p.Models {
		if model.Enabled && model.Provider == provider && model.Default {
			return model, true
		}
	}
	return Model{}, false
}

func validAssetPath(value string) error {
	if value == "" || filepath.IsAbs(value) || strings.Contains(value, "\\") || filepath.Clean(filepath.FromSlash(value)) != filepath.FromSlash(value) || value == "." || strings.HasPrefix(value, "../") {
		return errors.New("asset path must be clean and relative")
	}
	extension := strings.ToLower(filepath.Ext(value))
	if extension != ".svg" && extension != ".png" && extension != ".webp" {
		return errors.New("asset format is not allowed")
	}
	return nil
}
