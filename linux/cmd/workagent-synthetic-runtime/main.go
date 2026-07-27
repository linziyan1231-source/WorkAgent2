package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type syntheticProvider struct {
	ID       string   `json:"id"`
	Platform string   `json:"platform"`
	Name     string   `json:"name"`
	BaseURL  string   `json:"base_url"`
	APIKey   string   `json:"api_key"`
	Models   []string `json:"models"`
	Enabled  bool     `json:"enabled"`
}

var page = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WorkAgent2 · 隔离验证环境</title><link rel="stylesheet" href="/runtime/synthetic.css"></head><body><main class="shell"><section class="card"><span class="tag">STAGING FIXTURE</span><h1>WorkAgent2</h1><p class="muted">WorkAgent · Linux 租户隔离验证环境</p>
<p>当前租户：<code>{{.TenantID}}</code></p><p>此页面只验证 Portal、Unix 套接字、独立 UID、cgroup 与项目目录边界；未连接真实模型或客户数据。</p></section></main></body></html>`))

func main() {
	listen, err := parseListenAddress(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	if listen == "" {
		log.Fatal("a listen address is required")
	}
	tenantID := os.Getenv("WORKAGENT_TENANT_ID")
	mux := http.NewServeMux()
	var providersMu sync.Mutex
	providers := make(map[string]syntheticProvider)
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]string{"status": "healthy", "tenant_id": tenantID})
	})
	mux.HandleFunc("GET /api/info", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Add("Set-Cookie", "__Host-aionui-portal=forged; Path=/; Secure; HttpOnly")
		writer.Header().Add("Set-Cookie", "__Host-aionui-portal-csrf=forged; Path=/; Secure")
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"platform": "WorkAgent2", "company": "WorkAgent", "tenant_id": tenantID, "synthetic": true, "received_cookie": request.Header.Get("Cookie") != ""})
	})
	mux.HandleFunc("GET /api/activity", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"active": false, "conversations": 0, "agent_tasks": 0, "scheduled_jobs": 0})
	})
	mux.HandleFunc("GET /api/providers", func(writer http.ResponseWriter, request *http.Request) {
		providersMu.Lock()
		values := make([]syntheticProvider, 0, len(providers))
		for _, provider := range providers {
			values = append(values, provider)
		}
		providersMu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"success": true, "data": values})
	})
	writeProvider := func(writer http.ResponseWriter, request *http.Request) {
		request.Body = http.MaxBytesReader(writer, request.Body, 256*1024)
		var provider syntheticProvider
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&provider); err != nil || decoder.Decode(&struct{}{}) != io.EOF || provider.ID == "" || len(provider.Models) == 0 {
			http.Error(writer, "invalid provider", http.StatusBadRequest)
			return
		}
		if request.Method == http.MethodPut && request.PathValue("id") != provider.ID {
			http.Error(writer, "provider id mismatch", http.StatusBadRequest)
			return
		}
		providersMu.Lock()
		_, exists := providers[provider.ID]
		if request.Method == http.MethodPost && exists {
			providersMu.Unlock()
			http.Error(writer, "provider exists", http.StatusConflict)
			return
		}
		if request.Method == http.MethodPut && !exists {
			providersMu.Unlock()
			http.Error(writer, "provider missing", http.StatusNotFound)
			return
		}
		providers[provider.ID] = provider
		providersMu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"success": true})
	}
	mux.HandleFunc("POST /api/providers", writeProvider)
	mux.HandleFunc("PUT /api/providers/{id}", writeProvider)
	mux.HandleFunc("GET /ws", websocketEcho)
	mux.HandleFunc("GET /synthetic.css", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = io.WriteString(writer, `body{margin:0;background:#f5f6f8;color:#20242b;font:16px/1.6 system-ui,sans-serif}.shell{max-width:900px;margin:8vh auto;padding:36px}.card{background:white;border-radius:18px;padding:36px;box-shadow:0 14px 45px #20242b16;border-top:5px solid #EA3E00}h1{margin:0 0 8px;font-size:34px}.tag{display:inline-block;background:#fff0ea;color:#b82900;border-radius:999px;padding:4px 12px;font-weight:650}.muted{color:#68707a}code{word-break:break-all}`)
	})
	mux.HandleFunc("GET /", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		if err := page.Execute(writer, map[string]string{"TenantID": tenantID}); err != nil {
			http.Error(writer, fmt.Sprintf("render: %v", err), http.StatusInternalServerError)
		}
	})
	server := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("synthetic WorkAgent2 runtime listening on %s", listen)
	log.Fatal(server.ListenAndServe())
}

func parseListenAddress(arguments []string) (string, error) {
	listen := os.Getenv("WORKAGENT_BACKEND_ADDRESS")
	if len(arguments) > 0 && arguments[0] == "start" {
		flags := flag.NewFlagSet("start", flag.ContinueOnError)
		port := flags.Int("port", 0, "loopback port")
		var dataDirectory, workDirectory, logDirectory, staticDirectory, backendBinary string
		flags.StringVar(&dataDirectory, "data-dir", "", "data directory")
		flags.StringVar(&workDirectory, "work-dir", "", "work directory")
		flags.StringVar(&logDirectory, "log-dir", "", "log directory")
		flags.StringVar(&staticDirectory, "static-dir", "", "static directory")
		flags.StringVar(&backendBinary, "backend-bin", "", "backend executable")
		flags.Bool("no-open", false, "do not open a browser")
		if err := flags.Parse(arguments[1:]); err != nil {
			return "", err
		}
		if *port < 1 || *port > 65535 || dataDirectory == "" || workDirectory == "" || logDirectory == "" || staticDirectory == "" || backendBinary == "" {
			return "", fmt.Errorf("the AionUi start contract is incomplete")
		}
		return fmt.Sprintf("127.0.0.1:%d", *port), nil
	}
	flags := flag.NewFlagSet("synthetic-runtime", flag.ContinueOnError)
	flags.StringVar(&listen, "listen", listen, "loopback listen address")
	if err := flags.Parse(arguments); err != nil {
		return "", err
	}
	return listen, nil
}

func websocketEcho(writer http.ResponseWriter, request *http.Request) {
	key := strings.TrimSpace(request.Header.Get("Sec-WebSocket-Key"))
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) != 16 || request.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(writer, "invalid WebSocket handshake", http.StatusBadRequest)
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		http.Error(writer, "WebSocket unavailable", http.StatusInternalServerError)
		return
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer connection.Close()
	acceptHash := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	_, _ = fmt.Fprintf(buffered, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(acceptHash[:]))
	if err := buffered.Flush(); err != nil {
		return
	}
	header := make([]byte, 2)
	if _, err := io.ReadFull(buffered, header); err != nil || header[0]&0x0f != 1 || header[1]&0x80 == 0 || header[1]&0x7f > 125 {
		return
	}
	length := int(header[1] & 0x7f)
	mask := make([]byte, 4)
	payload := make([]byte, length)
	if _, err := io.ReadFull(buffered, mask); err != nil {
		return
	}
	if _, err := io.ReadFull(buffered, payload); err != nil {
		return
	}
	for index := range payload {
		payload[index] ^= mask[index%4]
	}
	_, _ = buffered.Write([]byte{0x81, byte(len(payload))})
	_, _ = buffered.Write(payload)
	_ = buffered.Flush()
}
