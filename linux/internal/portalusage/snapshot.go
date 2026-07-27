package portalusage

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"time"
)

const MaxSummarySnapshotBytes = 64 * 1024

// ParseSummarySnapshot applies the same strict wire contract in Portal and
// UserHost before a quota summary can enter tenant-private storage.
func ParseSummarySnapshot(payload []byte) (Summary, error) {
	if len(payload) == 0 || len(payload) > MaxSummarySnapshotBytes {
		return Summary{}, errors.New("usage snapshot size is invalid")
	}
	if err := rejectDuplicateJSONFields(payload); err != nil {
		return Summary{}, errors.New("usage snapshot JSON is invalid")
	}
	var summary Summary
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&summary); err != nil {
		return Summary{}, errors.New("usage snapshot JSON is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Summary{}, errors.New("usage snapshot must contain one JSON value")
	}
	if err := ValidateSummary(summary); err != nil {
		return Summary{}, err
	}
	return summary, nil
}

func rejectDuplicateJSONFields(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("usage snapshot contains trailing JSON")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, nested := token.(json.Delim)
	if !nested {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("usage snapshot object key is invalid")
			}
			if _, exists := seen[key]; exists {
				return errors.New("usage snapshot object key is duplicated")
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("usage snapshot object is incomplete")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("usage snapshot array is incomplete")
		}
	default:
		return errors.New("usage snapshot delimiter is invalid")
	}
	return nil
}

func MarshalSummarySnapshot(summary Summary) ([]byte, error) {
	if err := ValidateSummary(summary); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(summary)
	if err != nil {
		return nil, errors.New("encode usage snapshot")
	}
	if len(payload) == 0 || len(payload) > MaxSummarySnapshotBytes {
		return nil, errors.New("usage snapshot size is invalid")
	}
	return payload, nil
}

func ValidateSummary(summary Summary) error {
	if !validSnapshotTime(summary.AsOf) || len(summary.Providers) != 2 {
		return errors.New("usage snapshot timestamp or provider count is invalid")
	}
	seen := make(map[string]struct{}, 2)
	for _, provider := range summary.Providers {
		if provider.Kind != KindChatGPT && provider.Kind != KindKimi {
			return errors.New("usage snapshot provider kind is invalid")
		}
		if _, exists := seen[provider.Kind]; exists {
			return errors.New("usage snapshot provider kind is duplicated")
		}
		seen[provider.Kind] = struct{}{}
		expectedLabel := "ChatGPT"
		if provider.Kind == KindKimi {
			expectedLabel = "Kimi"
		}
		if provider.Label != expectedLabel || !validSummaryWindow(provider.Daily) || !validSummaryWindow(provider.Weekly) {
			return errors.New("usage snapshot provider is invalid")
		}
		if provider.Pro != nil {
			if provider.Kind != KindChatGPT || provider.Pro.Used < 0 || provider.Pro.Limit <= 0 || !validSnapshotTime(provider.Pro.ResetAt) {
				return errors.New("usage snapshot Pro quota is invalid")
			}
		}
	}
	if _, exists := seen[KindChatGPT]; !exists {
		return errors.New("usage snapshot ChatGPT provider is missing")
	}
	if _, exists := seen[KindKimi]; !exists {
		return errors.New("usage snapshot Kimi provider is missing")
	}
	if summary.Storage != nil {
		if err := ValidateStorageUsage(*summary.Storage); err != nil {
			return err
		}
	}
	return nil
}

func ValidateStorageUsage(storage StorageUsage) error {
	if storage.LimitBytes == 0 || !validSnapshotTime(storage.MeasuredAt) {
		return errors.New("usage snapshot storage measurement is invalid")
	}
	expectedRemaining := uint64(0)
	if storage.UsedBytes < storage.LimitBytes {
		expectedRemaining = storage.LimitBytes - storage.UsedBytes
	}
	if storage.RemainingBytes != expectedRemaining {
		return errors.New("usage snapshot storage remainder is invalid")
	}
	return nil
}

func validSummaryWindow(window Window) bool {
	limit, err := parseDecimal(window.LimitUSD)
	if err != nil || limit.Sign() <= 0 || formatUSD(limit) != window.LimitUSD {
		return false
	}
	used, err := parseDecimal(window.UsedUSD)
	if err != nil || formatUSD(used) != window.UsedUSD {
		return false
	}
	remaining, err := parseDecimal(window.RemainingUSD)
	if err != nil || formatUSD(remaining) != window.RemainingUSD {
		return false
	}
	expected := new(big.Rat).Sub(limit, used)
	if expected.Sign() < 0 {
		expected.SetInt64(0)
	}
	difference := new(big.Rat).Sub(remaining, expected)
	if difference.Sign() < 0 {
		difference.Neg(difference)
	}
	// The Management API can report sub-cent usage. normalizeWindow rounds the
	// displayed used and remaining values independently, so their displayed
	// arithmetic can differ by one cent while still representing the same raw
	// measurement.
	return difference.Cmp(big.NewRat(1, 100)) <= 0 && validSnapshotTime(window.ResetAt)
}

func validSnapshotTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && parsed.UTC().Format(time.RFC3339) == value
}
