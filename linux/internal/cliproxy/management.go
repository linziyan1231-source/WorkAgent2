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
	"time"
)

const maxManagementResponse = 2 * 1024 * 1024

var (
	managementKeyPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)
	managementRoutePattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,160}$`)
)

type ManagementOptions struct {
	BaseURL string
	KeyFile string
}

type ManagementClient struct {
	baseURL string
	origin  string
	key     []byte
	http    *http.Client
}

func NewManagementClient(options ManagementOptions) (*ManagementClient, error) {
	base, err := url.Parse(options.BaseURL)
	if err != nil || base.Scheme != "http" || (base.Hostname() != "127.0.0.1" && base.Hostname() != "::1") || base.Port() == "" || base.User != nil ||
		base.Path != "/v0/management/plugins/cpa-key-policy" || base.RawQuery != "" || base.Fragment != "" || strings.HasSuffix(options.BaseURL, "/") {
		return nil, errors.New("CLIProxy policy Management API URL must be an exact loopback HTTP URL")
	}
	if !filepath.IsAbs(options.KeyFile) || filepath.Clean(options.KeyFile) != options.KeyFile {
		return nil, errors.New("CLIProxy management key file must be a clean absolute path")
	}
	info, err := os.Lstat(options.KeyFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() < 32 || info.Size() > 1024 {
		return nil, errors.New("CLIProxy management key file must be a protected bounded regular file")
	}
	data, err := os.ReadFile(options.KeyFile)
	if err != nil {
		return nil, errors.New("CLIProxy management key file could not be read")
	}
	key := bytes.TrimSpace(data)
	if !managementKeyPattern.Match(key) {
		clear(data)
		return nil, errors.New("CLIProxy management key has invalid content")
	}
	keyCopy := append([]byte(nil), key...)
	clear(data)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &ManagementClient{baseURL: options.BaseURL, origin: base.Scheme + "://" + base.Host, key: keyCopy, http: &http.Client{Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *ManagementClient) Close() {
	if c == nil {
		return
	}
	clear(c.key)
	c.key = nil
}

func (c *ManagementClient) JSON(ctx context.Context, method, route string, input, output any) error {
	if c == nil || c.http == nil || !managementRoutePattern.MatchString(route) || strings.Contains(route, "..") {
		return errors.New("CLIProxy management request is invalid")
	}
	return c.jsonAt(ctx, method, c.baseURL+route, input, output)
}

// keyUsage performs the one management read that requires a query parameter.
// The route and parameter name are fixed, and the id must satisfy the policy
// key-id contract; callers cannot use this helper to construct an arbitrary
// management URL. The GET deliberately has no request body.
func (c *ManagementClient) keyUsage(ctx context.Context, id string, output any) error {
	if c == nil || c.http == nil || !policyKeyIDPattern.MatchString(id) || output == nil {
		return errors.New("CLIProxy key usage request is invalid")
	}
	target := c.baseURL + "/keys/usage?id=" + url.QueryEscape(id)
	data, _, err := c.request(ctx, http.MethodGet, target, nil, maxManagementResponse)
	if err != nil {
		return err
	}
	defer clear(data)
	return decodeManagementJSON(data, output)
}

func (c *ManagementClient) coreJSON(ctx context.Context, method, route string, output any) (http.Header, error) {
	target, err := c.coreTarget(route)
	if err != nil {
		return nil, err
	}
	data, headers, err := c.request(ctx, method, target, nil, maxManagementResponse)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	if output == nil {
		return headers, nil
	}
	if err := decodeManagementJSON(data, output); err != nil {
		return nil, err
	}
	return headers, nil
}

func (c *ManagementClient) coreRaw(ctx context.Context, route string, maximum int64) ([]byte, http.Header, error) {
	target, err := c.coreTarget(route)
	if err != nil || maximum < 1 || maximum > maxManagementResponse {
		return nil, nil, errors.New("CLIProxy management request is invalid")
	}
	return c.request(ctx, http.MethodGet, target, nil, maximum)
}

func (c *ManagementClient) coreTarget(route string) (string, error) {
	if c == nil || c.http == nil || !managementRoutePattern.MatchString(route) || strings.Contains(route, "..") || !strings.HasPrefix(route, "/v0/management/") {
		return "", errors.New("CLIProxy management request is invalid")
	}
	return c.origin + route, nil
}

func (c *ManagementClient) jsonAt(ctx context.Context, method, target string, input, output any) error {
	data, _, err := c.request(ctx, method, target, input, maxManagementResponse)
	if err != nil {
		return err
	}
	defer clear(data)
	if output == nil {
		return nil
	}
	return decodeManagementJSON(data, output)
}

func (c *ManagementClient) request(ctx context.Context, method, target string, input any, maximum int64) ([]byte, http.Header, error) {
	var body io.Reader
	var encoded []byte
	if input != nil {
		var err error
		encoded, err = json.Marshal(input)
		if err != nil {
			return nil, nil, errors.New("encode CLIProxy management request")
		}
		defer clear(encoded)
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, nil, errors.New("create CLIProxy management request")
	}
	request.Header.Set("Authorization", "Bearer "+string(c.key))
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, errors.New("CLIProxy management connection failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		clear(data)
		return nil, nil, errors.New("CLIProxy management response was unreadable or oversized")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		clear(data)
		return nil, nil, fmt.Errorf("CLIProxy management API returned HTTP %d", response.StatusCode)
	}
	return data, response.Header.Clone(), nil
}

func decodeManagementJSON(data []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(output); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("CLIProxy management API returned invalid JSON")
	}
	return nil
}
