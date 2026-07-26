package userhost

import (
	"errors"
	"testing"
)

func TestCoreHealthMonitorDebouncesOnlyTransientFailures(t *testing.T) {
	transient := &coreHealthError{transient: true, err: errors.New("temporary timeout")}
	consecutive := 0
	for attempt := 1; attempt <= coreHealthTransientFailureThreshold; attempt++ {
		var fail bool
		consecutive, fail = coreHealthMonitorDecision(consecutive, transient)
		if fail != (attempt == coreHealthTransientFailureThreshold) {
			t.Fatalf("attempt %d fail=%t consecutive=%d", attempt, fail, consecutive)
		}
	}

	consecutive, fail := coreHealthMonitorDecision(2, errors.New("wrong health version"))
	if !fail || consecutive != 0 {
		t.Fatalf("permanent failure decision fail=%t consecutive=%d", fail, consecutive)
	}
}
