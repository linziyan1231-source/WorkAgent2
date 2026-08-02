package portalusage

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"sync"
	"time"

	"aionuiportal/internal/modelbootstrap"
)

const (
	KindChatGPT = "chatgpt"
	KindKimi    = "kimi"
)

var decimalPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})(\.[0-9]{1,24})?$`)

type Window struct {
	LimitUSD     string `json:"limit_usd"`
	UsedUSD      string `json:"used_usd"`
	RemainingUSD string `json:"remaining_usd"`
	ResetAt      string `json:"reset_at"`
}

type Provider struct {
	Kind   string       `json:"kind"`
	Label  string       `json:"label"`
	Daily  Window       `json:"daily"`
	Weekly Window       `json:"weekly"`
	Pro    *CountWindow `json:"pro,omitempty"`
}

type CountWindow struct {
	Used    int    `json:"used"`
	Limit   int    `json:"limit"`
	ResetAt string `json:"reset_at"`
}

type StorageUsage struct {
	LimitBytes     uint64 `json:"limit_bytes"`
	UsedBytes      uint64 `json:"used_bytes"`
	RemainingBytes uint64 `json:"remaining_bytes"`
	MeasuredAt     string `json:"measured_at"`
}

type Summary struct {
	AsOf      string        `json:"as_of"`
	Providers []Provider    `json:"providers"`
	Storage   *StorageUsage `json:"storage,omitempty"`
}

type RawWindow struct {
	LimitUSD string `json:"limit_usd"`
	UsedUSD  string `json:"used_usd"`
	ResetAt  string `json:"reset_at"`
}

type RawProvider struct {
	Kind   string    `json:"kind"`
	Daily  RawWindow `json:"daily"`
	Weekly RawWindow `json:"weekly"`
}

type RawSnapshot struct {
	AsOf      string        `json:"as_of"`
	Providers []RawProvider `json:"providers"`
}

type Remote interface {
	Query(context.Context, modelbootstrap.KeyIDs) (RawSnapshot, error)
}

type cacheEntry struct {
	expires time.Time
	value   Summary
}

type Service struct {
	remote Remote
	ttl    time.Duration
	now    func() time.Time
	mu     sync.Mutex
	cache  map[string]cacheEntry
}

func NewService(remote Remote, ttl time.Duration, now func() time.Time) (*Service, error) {
	if remote == nil || ttl <= 0 {
		return nil, errors.New("Portal usage remote and positive cache TTL are required")
	}
	if now == nil {
		now = time.Now
	}
	return &Service{remote: remote, ttl: ttl, now: now, cache: make(map[string]cacheEntry)}, nil
}

func (s *Service) Current(ctx context.Context, windowsSID string, ids modelbootstrap.KeyIDs) (Summary, error) {
	if err := ids.ValidateForSID(windowsSID); err != nil {
		return Summary{}, fmt.Errorf("validate current-user model mapping: %w", err)
	}
	cacheKey := strings.ToUpper(windowsSID)
	now := s.now()
	s.mu.Lock()
	entry, found := s.cache[cacheKey]
	s.mu.Unlock()
	if found && now.Before(entry.expires) {
		return cloneSummary(entry.value), nil
	}

	raw, err := s.remote.Query(ctx, ids)
	if err != nil {
		return Summary{}, fmt.Errorf("query remote usage: %w", err)
	}
	value, err := normalize(raw)
	if err != nil {
		return Summary{}, fmt.Errorf("validate remote usage: %w", err)
	}
	s.mu.Lock()
	s.cache[cacheKey] = cacheEntry{expires: s.now().Add(s.ttl), value: cloneSummary(value)}
	s.mu.Unlock()
	return value, nil
}

func normalize(raw RawSnapshot) (Summary, error) {
	asOf, err := time.Parse(time.RFC3339, raw.AsOf)
	if err != nil || len(raw.Providers) != 2 {
		return Summary{}, errors.New("remote usage timestamp or provider count is invalid")
	}
	byKind := make(map[string]RawProvider, 2)
	for _, provider := range raw.Providers {
		if provider.Kind != KindChatGPT && provider.Kind != KindKimi {
			return Summary{}, errors.New("remote usage provider kind is invalid")
		}
		if _, exists := byKind[provider.Kind]; exists {
			return Summary{}, errors.New("remote usage provider kind is duplicated")
		}
		byKind[provider.Kind] = provider
	}
	providers := make([]Provider, 0, 2)
	for _, item := range []struct {
		kind  string
		label string
	}{{KindChatGPT, "ChatGPT"}, {KindKimi, "Kimi"}} {
		rawProvider, exists := byKind[item.kind]
		if !exists {
			return Summary{}, errors.New("remote usage provider is missing")
		}
		daily, err := normalizeWindow(rawProvider.Daily)
		if err != nil {
			return Summary{}, fmt.Errorf("%s daily usage is invalid: %w", item.kind, err)
		}
		weekly, err := normalizeWindow(rawProvider.Weekly)
		if err != nil {
			return Summary{}, fmt.Errorf("%s weekly usage is invalid: %w", item.kind, err)
		}
		providers = append(providers, Provider{Kind: item.kind, Label: item.label, Daily: daily, Weekly: weekly})
	}
	return Summary{AsOf: asOf.UTC().Format(time.RFC3339), Providers: providers}, nil
}

func normalizeWindow(raw RawWindow) (Window, error) {
	limit, err := parseDecimal(raw.LimitUSD)
	if err != nil || limit.Sign() <= 0 {
		return Window{}, errors.New("limit must be a positive decimal")
	}
	used, err := parseDecimal(raw.UsedUSD)
	if err != nil {
		return Window{}, errors.New("used amount must be a non-negative decimal")
	}
	remaining := new(big.Rat).Sub(limit, used)
	if remaining.Sign() < 0 {
		remaining.SetInt64(0)
	}
	resetAt, err := time.Parse(time.RFC3339, raw.ResetAt)
	if err != nil {
		return Window{}, errors.New("reset time must be RFC3339")
	}
	return Window{LimitUSD: formatUSD(limit), UsedUSD: formatUSD(used), RemainingUSD: formatUSD(remaining), ResetAt: resetAt.UTC().Format(time.RFC3339)}, nil
}

func parseDecimal(value string) (*big.Rat, error) {
	if !decimalPattern.MatchString(value) {
		return nil, errors.New("unsupported decimal")
	}
	amount, ok := new(big.Rat).SetString(value)
	if !ok || amount.Sign() < 0 {
		return nil, errors.New("invalid decimal")
	}
	return amount, nil
}

func formatUSD(value *big.Rat) string {
	scaled := new(big.Rat).Mul(value, big.NewRat(100, 1))
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(scaled.Num(), scaled.Denom(), remainder)
	if new(big.Int).Lsh(remainder, 1).Cmp(scaled.Denom()) >= 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	dollars, cents := new(big.Int), new(big.Int)
	dollars.QuoRem(quotient, big.NewInt(100), cents)
	return fmt.Sprintf("%s.%02d", dollars.String(), cents.Int64())
}

func cloneSummary(value Summary) Summary {
	value.Providers = append([]Provider(nil), value.Providers...)
	if value.Storage != nil {
		storage := *value.Storage
		value.Storage = &storage
	}
	return value
}
