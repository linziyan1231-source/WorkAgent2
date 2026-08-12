package cliproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const maxManagementResponse = 2 * 1024 * 1024

var managementKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{40,256}$`)

type ManagementOptions struct {
	BaseURL string
	KeyFile string
}

type ManagementClient struct {
	baseURL string
	key     string
	http    *http.Client
}

func NewManagementClient(options ManagementOptions) (*ManagementClient, error) {
	base, err := url.Parse(options.BaseURL)
	if err != nil || base.Scheme != "http" || base.Hostname() != "127.0.0.1" || base.Port() == "" || base.User != nil ||
		base.Path != "/v0/management/plugins/cpa-key-policy" || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("CLIProxyAPI policy Management API URL must be an exact IPv4 loopback HTTP URL")
	}
	if !filepath.IsAbs(options.KeyFile) {
		return nil, errors.New("CLIProxyAPI management key file must be absolute")
	}
	info, err := os.Lstat(options.KeyFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 1024 {
		return nil, errors.New("CLIProxyAPI management key file must be a bounded regular non-symlink file")
	}
	data, err := os.ReadFile(options.KeyFile)
	if err != nil {
		return nil, errors.New("CLIProxyAPI management key file could not be read")
	}
	key := strings.TrimSpace(string(data))
	clear(data)
	if !managementKeyPattern.MatchString(key) {
		return nil, errors.New("CLIProxyAPI management key file has invalid content")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &ManagementClient{baseURL: strings.TrimRight(options.BaseURL, "/"), key: key, http: &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}, nil
}

func (c *ManagementClient) JSON(ctx context.Context, method, route string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return errors.New("encode CLIProxyAPI management request")
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+route, body)
	if err != nil {
		return errors.New("create CLIProxyAPI management request")
	}
	request.Header.Set("Authorization", "Bearer "+c.key)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("CLIProxyAPI management API connection failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxManagementResponse+1))
	if err != nil || len(data) > maxManagementResponse {
		return errors.New("CLIProxyAPI management response was unreadable or oversized")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("CLIProxyAPI management API returned HTTP %d", response.StatusCode)
	}
	if output == nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(output); err != nil {
		return errors.New("CLIProxyAPI management API returned invalid JSON")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("CLIProxyAPI management API returned trailing JSON")
	}
	return nil
}
