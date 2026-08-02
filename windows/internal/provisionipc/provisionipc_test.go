package provisionipc

import (
	"bytes"
	"testing"
)

func TestReadFrameReadsProgressBeforeFinalResponse(t *testing.T) {
	var stream bytes.Buffer
	if err := writeFrame(&stream, Response{Progress: &Progress{Percent: 42, Step: "applying_security_policy"}}); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(&stream, Response{OK: true, User: &User{Username: "employee-two"}}); err != nil {
		t.Fatal(err)
	}
	var progress Response
	if err := readFrame(&stream, &progress); err != nil || progress.Progress == nil || progress.Progress.Percent != 42 {
		t.Fatalf("read progress frame: response=%+v err=%v", progress, err)
	}
	var completed Response
	if err := readFrame(&stream, &completed); err != nil || !completed.OK || completed.User == nil || completed.User.Username != "employee-two" {
		t.Fatalf("read final frame: response=%+v err=%v", completed, err)
	}
}
