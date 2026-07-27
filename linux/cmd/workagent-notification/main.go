package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/notificationsvc"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:25888", "numeric loopback listen address")
	payload := flag.String("payload", "/etc/workagent/notification.json", "protected notification JSON")
	credential := flag.String("credential", "/run/credentials/workagent-notification.service/notifications-key", "systemd credential file")
	flag.Parse()
	logger := log.New(os.Stderr, "workagent-notification: ", log.LstdFlags|log.LUTC)
	service, err := notificationsvc.New(notificationsvc.Config{ListenAddress: *listen, PayloadFile: *payload, CredentialFile: *credential, Logger: logger})
	if err != nil {
		logger.Fatal(err)
	}
	defer service.Close()
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err := service.Serve(server); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Fatal(err)
	}
}
