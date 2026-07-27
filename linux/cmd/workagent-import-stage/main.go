//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/stagepublish"
)

func main() {
	flags := flag.NewFlagSet("workagent-import-stage", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stage := flags.String("stage", "", "root-owned completed Linux migration stage")
	expectedSource := flags.String("expected-source-fingerprint", "", "reviewed source fingerprint")
	expectedOutput := flags.String("expected-output-fingerprint", "", "reviewed output fingerprint")
	check := flags.Bool("check", false, "validate without changing production state")
	apply := flags.Bool("apply", false, "publish into the fixed production layout")
	confirm := flags.String("confirm", "", "required exact publication confirmation token")
	if err := flags.Parse(os.Args[1:]); err != nil || flags.NArg() != 0 {
		fatal("usage: workagent-import-stage (--check | --apply --confirm " + stagepublish.ConfirmPublication + ") --stage ABSOLUTE_PATH --expected-source-fingerprint SHA256 --expected-output-fingerprint SHA256")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
	defer cancel()
	result, err := stagepublish.Run(ctx, stagepublish.Options{
		Stage: *stage, ExpectedSourceFingerprint: *expectedSource, ExpectedOutputFingerprint: *expectedOutput,
		Check: *check, Apply: *apply, Confirm: *confirm,
	})
	if err != nil {
		fatal(err.Error())
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(result); err != nil {
		fatal("encode publication result")
	}
}

func fatal(message string) {
	message = strings.TrimSpace(message)
	if message == "" || len(message) > 1024 || strings.ContainsAny(message, "\r\n") {
		message = "operation failed; detailed output was redacted"
	}
	fmt.Fprintln(os.Stderr, "workagent-import-stage:", message)
	os.Exit(1)
}
