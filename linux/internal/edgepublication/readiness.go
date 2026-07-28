package edgepublication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"
)

// ReadinessComponent is one named Portal readiness component.
type ReadinessComponent struct {
	Ready bool `json:"ready"`
}

// ReadinessReport is the exact Portal /readyz evidence shape admitted for
// edge publication.
type ReadinessReport struct {
	Status     string                        `json:"status"`
	Ready      bool                          `json:"ready"`
	CheckedAt  time.Time                     `json:"checked_at"`
	PolicyID   string                        `json:"policy_id"`
	BrandID    string                        `json:"brand_id"`
	Components map[string]ReadinessComponent `json:"components"`
}

func ProbeReadiness(ctx context.Context, client *http.Client, endpoint, host string, attestForwardedHTTPS, retry bool) (ReadinessReport, error) {
	attempts := 1
	if retry {
		attempts = 16
	}
	var failures []error
	for attempt := 1; attempt <= attempts; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return ReadinessReport{}, err
		}
		request.Host = host
		if attestForwardedHTTPS {
			request.Header.Set("X-Forwarded-Proto", "https")
		}
		response, requestErr := client.Do(request)
		if requestErr == nil {
			report, responseErr := decodeReadinessResponse(response)
			if responseErr == nil {
				return report, nil
			}
			failures = append(failures, responseErr)
		} else {
			failures = append(failures, requestErr)
		}
		if attempt < attempts {
			select {
			case <-ctx.Done():
				return ReadinessReport{}, errors.Join(errors.New("Portal readiness probe was cancelled"), ctx.Err(), errors.Join(failures...))
			case <-time.After(5 * time.Second):
			}
		}
	}
	return ReadinessReport{}, errors.Join(errors.New("Portal readiness endpoint did not become ready"), errors.Join(failures...))
}

func decodeReadinessResponse(response *http.Response) (ReadinessReport, error) {
	if response == nil || response.Body == nil {
		return ReadinessReport{}, errors.New("Portal readiness response is unavailable")
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaErr != nil || mediaType != "application/json" || response.ContentLength > 256*1024 {
		return ReadinessReport{}, errors.New("Portal readiness endpoint did not return an exact JSON success")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 256*1024+1))
	if err != nil || len(payload) == 0 || len(payload) > 256*1024 {
		return ReadinessReport{}, errors.Join(errors.New("Portal readiness response is invalid or oversized"), err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var report ReadinessReport
	if err := decoder.Decode(&report); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ReadinessReport{}, errors.New("Portal readiness response is invalid or oversized")
	}
	return report, nil
}

func ValidateReadinessReport(report ReadinessReport, now time.Time, expectedPolicyID, expectedBrandID string) error {
	required := []string{"audit", "brand", "chat_forward", "cli_proxy", "database", "host", "notifications", "policy", "renderer", "tenants"}
	now = now.UTC()
	if expectedPolicyID == "" || expectedBrandID == "" || report.Status != "ready" || !report.Ready || report.CheckedAt.Before(now.Add(-30*time.Second)) || report.CheckedAt.After(now.Add(5*time.Second)) || report.PolicyID != expectedPolicyID || report.BrandID != expectedBrandID || len(report.Components) != len(required) {
		return errors.New("Portal readiness response is incomplete")
	}
	for _, component := range required {
		if !report.Components[component].Ready {
			return fmt.Errorf("Portal readiness component %s is not ready", component)
		}
	}
	return nil
}
