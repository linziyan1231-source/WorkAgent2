package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const provisionStateVersion = 1

type provisionState struct {
	Version        int       `json:"version"`
	Username       string    `json:"username"`
	WindowsSID     string    `json:"windows_sid,omitempty"`
	CurrentStep    string    `json:"current_step,omitempty"`
	CompletedSteps []string  `json:"completed_steps,omitempty"`
	Status         string    `json:"status"`
	FailureStage   string    `json:"failure_stage,omitempty"`
	ResumeStep     string    `json:"resume_step,omitempty"`
	ErrorCode      string    `json:"error_code,omitempty"`
	Attempt        int       `json:"attempt"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type provisionStateStore struct {
	directory string
	now       func() time.Time
}

func (s provisionStateStore) open(username string) (*provisionState, error) {
	path := s.path(username)
	state := &provisionState{Version: provisionStateVersion, Username: username, Status: "pending"}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		state.Attempt = 1
		state.UpdatedAt = s.now().UTC()
		return state, s.save(state)
	}
	if err != nil {
		return nil, fmt.Errorf("read provisioning state: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(state); err != nil || state.Version != provisionStateVersion || !strings.EqualFold(state.Username, username) {
		return nil, errors.New("persisted provisioning state is invalid")
	}
	if state.Status == "complete" {
		return state, nil
	}
	if state.FailureStage != "" {
		state.ResumeStep = state.FailureStage
	} else if state.CurrentStep != "" {
		state.ResumeStep = state.CurrentStep
	}
	state.Attempt++
	state.Status = "pending"
	state.FailureStage = ""
	state.ErrorCode = ""
	state.UpdatedAt = s.now().UTC()
	return state, s.save(state)
}

func (s provisionStateStore) begin(state *provisionState, step string) error {
	state.CurrentStep = step
	state.ResumeStep = step
	state.Status = "running"
	state.FailureStage = ""
	state.ErrorCode = ""
	state.UpdatedAt = s.now().UTC()
	return s.save(state)
}

func (s provisionStateStore) complete(state *provisionState, step string) error {
	if !containsProvisionStep(state.CompletedSteps, step) {
		state.CompletedSteps = append(state.CompletedSteps, step)
	}
	state.CurrentStep = ""
	state.Status = "pending"
	state.UpdatedAt = s.now().UTC()
	return s.save(state)
}

func (s provisionStateStore) fail(state *provisionState, step string) error {
	state.CurrentStep = ""
	state.Status = "failed"
	state.FailureStage = step
	state.ResumeStep = step
	state.ErrorCode = "STEP_FAILED"
	state.UpdatedAt = s.now().UTC()
	return s.save(state)
}

func (s provisionStateStore) finish(state *provisionState) error {
	state.CurrentStep = ""
	state.Status = "complete"
	state.FailureStage = ""
	state.ResumeStep = ""
	state.ErrorCode = ""
	state.UpdatedAt = s.now().UTC()
	return s.save(state)
}

func (s provisionStateStore) save(state *provisionState) error {
	var lastErr error
	for attempt := 0; attempt < 20; attempt++ {
		if err := writeJSONAtomic(s.path(state.Username), state); err == nil {
			return nil
		} else {
			lastErr = err
		}
		// Windows Defender/indexing may briefly retain the replaced journal.
		// A bounded retry preserves atomic replacement without deleting the last
		// durable state or falling back to an in-place write.
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("atomically replace provisioning state: %w", lastErr)
}

func (s provisionStateStore) path(username string) string {
	// Local usernames are already lexically validated before this store is used.
	return filepath.Join(s.directory, strings.ToLower(username)+".json")
}

func containsProvisionStep(steps []string, step string) bool {
	for _, completed := range steps {
		if completed == step {
			return true
		}
	}
	return false
}

type provisionLocks struct {
	mu     sync.Mutex
	active map[string]struct{}
}

func (l *provisionLocks) acquire(username string) (func(), error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active == nil {
		l.active = make(map[string]struct{})
	}
	key := strings.ToLower(username)
	if _, exists := l.active[key]; exists {
		return nil, errors.New("provisioning is already running for this username")
	}
	l.active[key] = struct{}{}
	return func() {
		l.mu.Lock()
		delete(l.active, key)
		l.mu.Unlock()
	}, nil
}
