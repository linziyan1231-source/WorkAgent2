package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"aionuiportal/internal/config"
	"aionuiportal/internal/userhost"
)

func main() {
	os.Exit(run())
}

func run() int {
	flags := flag.NewFlagSet("aionui-userhost", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "", "absolute path to the fixed UserHost configuration")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if *configPath == "" || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: AionUiUserHost.exe --config <absolute-path>")
		return 2
	}
	cfg, err := config.LoadUserHost(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "UserHost configuration error: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := userhost.Run(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "UserHost stopped with an error: %v\n", err)
		return 1
	}
	return 0
}
