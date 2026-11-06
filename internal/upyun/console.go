package upyun

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"time"
)

const consoleBase = "https://console.upyun.com"

// ConsoleClient talks to console.upyun.com, whose account session is the only
// supported way to upload and bind certificates. The open API is read-only for
// certificates and returns 22308 for writes.
type ConsoleClient struct {
	Username string
	Password string
	BaseURL  string
	HTTP     *http.Client

	mu       sync.Mutex
	loggedIn bool
}

func NewConsole(username, password string) *ConsoleClient {
	jar, _ := cookiejar.New(nil)
	return &ConsoleClient{
		Username: username,
		Password: password,
		BaseURL:  consoleBase,
		HTTP:     &http.Client{Jar: jar, Timeout: 60 * time.Second},
	}
}

func (c *ConsoleClient) Login(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.login(ctx)
}

func (c *ConsoleClient) login(ctx context.Context) error {
	data, err := c.callOnce(ctx, http.MethodPost, "/accounts/signin/", map[string]string{
		"username": c.Username,
		"password": c.Password,
	})
	if err != nil {
		c.loggedIn = false
		return fmt.Errorf("upyun console sign-in: %w", err)
	}
	var out struct {
		Result bool `json:"result"`
	}
	if len(data) > 0 {
		_ = json.Unmarshal(data, &out)
	}
	if !out.Result {
		c.loggedIn = false
		return fmt.Errorf("upyun console sign-in rejected")
	}
	c.loggedIn = true
	return nil
}

func (c *ConsoleClient) ensureLogin(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loggedIn {
		return nil
	}
	return c.login(ctx)
}

func (c *ConsoleClient) relogin(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loggedIn = false
	return c.login(ctx)
}

func (c *ConsoleClient) call(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	if err := c.ensureLogin(ctx); err != nil {
		return nil, err
	}
	data, err := c.callOnce(ctx, method, path, body)
	var apiErr *consoleError
	if asConsoleError(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
		if lerr := c.relogin(ctx); lerr == nil {
			return c.callOnce(ctx, method, path, body)
		}
	}
	return data, err
}

func (c *ConsoleClient) callOnce(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}

	var env struct {
		Data   json.RawMessage   `json:"data"`
		Errors []json.RawMessage `json:"errors"`
		Msg    json.RawMessage   `json:"msg"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		if resp.StatusCode/100 != 2 {
			return nil, &consoleError{Status: resp.StatusCode, Message: string(raw)}
		}
		return nil, fmt.Errorf("upyun console: invalid JSON response")
	}

	var failed struct {
		ErrorCode json.Number `json:"error_code"`
		Message   string      `json:"message"`
	}
	if len(env.Data) > 0 {
		_ = json.Unmarshal(env.Data, &failed)
	}
	code, _ := failed.ErrorCode.Int64()
	switch {
	case code != 0:
		return nil, &consoleError{Status: resp.StatusCode, Code: code, Message: failed.Message}
	case len(env.Errors) > 0 || resp.StatusCode/100 != 2:
		return nil, &consoleError{Status: resp.StatusCode, Message: string(env.Msg)}
	}
	return env.Data, nil
}

type consoleError struct {
	Status  int
	Code    int64
	Message string
}

func (e *consoleError) Error() string {
	return fmt.Sprintf("upyun console: http %d code=%d: %s", e.Status, e.Code, e.Message)
}

func asConsoleError(err error, target **consoleError) bool {
	if e, ok := err.(*consoleError); ok {
		*target = e
		return true
	}
	return false
}

func (c *ConsoleClient) UploadCertificate(ctx context.Context, certPEM, keyPEM, name string) (string, error) {
	data, err := c.call(ctx, http.MethodPost, "/api/https/certificate/", map[string]string{
		"certificate": certPEM,
		"private_key": keyPEM,
	})
	if err != nil {
		return "", fmt.Errorf("upload certificate: %w", err)
	}
	var out struct {
		Result struct {
			CertID string `json:"certificate_id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("upload certificate: decode: %w", err)
	}
	if out.Result.CertID == "" {
		return "", fmt.Errorf("upload certificate: no certificate_id in response")
	}
	return out.Result.CertID, nil
}

// MigrateCertificate moves every HTTPS domain configured on oldID to newID.
// Upyun's console UI calls this "域名 HTTPS 配置迁移"; it is the supported
// replacement flow and preserves force/source HTTPS settings.
func (c *ConsoleClient) MigrateCertificate(ctx context.Context, oldID, newID string) error {
	if oldID == "" || newID == "" || oldID == newID {
		return nil
	}
	if _, err := c.call(ctx, http.MethodPost, "/api/https/migrate/certificate", map[string]string{
		"old_crt_id": oldID,
		"new_crt_id": newID,
	}); err != nil {
		return fmt.Errorf("migrate certificate %s -> %s: %w", oldID, newID, err)
	}
	return nil
}

func (c *ConsoleClient) Bindings(ctx context.Context, domain string) ([]Binding, error) {
	data, err := c.call(ctx, http.MethodGet, "/api/https/services/manager?"+url.Values{"domain": {domain}}.Encode(), nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Result []struct {
			CertID      string `json:"certificate_id"`
			HTTPS       bool   `json:"https"`
			ForceHTTPS  bool   `json:"force_https"`
			SourceHTTPS bool   `json:"source_https"`
			Validity    struct {
				End int64 `json:"end"`
			} `json:"validity"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	rows := make([]Binding, 0, len(out.Result))
	for _, b := range out.Result {
		rows = append(rows, Binding{
			CertID:      b.CertID,
			HTTPS:       b.HTTPS,
			ForceHTTPS:  b.ForceHTTPS,
			SourceHTTPS: b.SourceHTTPS,
			NotAfter:    time.UnixMilli(b.Validity.End),
		})
	}
	return rows, nil
}

func (c *ConsoleClient) BindCertificate(ctx context.Context, domain, certID string, https, forceHTTPS, sourceHTTPS bool) error {
	body := map[string]any{
		"certificate_id": certID,
		"domain":         domain,
		"https":          https,
		"force_https":    forceHTTPS,
		"source_https":   sourceHTTPS,
	}
	if _, err := c.call(ctx, http.MethodPost, "/api/https/certificate/manager/", body); err != nil {
		var ce *consoleError
		if asConsoleError(err, &ce) && ce.Code == 21713 {
			if _, merr := c.call(ctx, http.MethodPost, "/api/https/migrate/domain", map[string]string{
				"crt_id":      certID,
				"domain_name": domain,
			}); merr != nil {
				return fmt.Errorf("bind %s: migrate: %w", domain, merr)
			}
			return nil
		}
		return fmt.Errorf("bind %s: %w", domain, err)
	}
	return nil
}
