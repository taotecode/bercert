package upyun

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const apiBase = "https://api.upyun.com"

type Client struct {
	Token string
	HTTP  *http.Client
}

type Domain struct {
	Bucket string
	Domain string
	Status string
	HTTPS  string
}

type Certificate struct {
	ID         string
	CommonName string
	NotAfter   time.Time
	Configed   int
	Type       string
}

type Binding struct {
	CertID      string
	HTTPS       bool
	ForceHTTPS  bool
	SourceHTTPS bool
	NotAfter    time.Time
}

func New(token string) *Client {
	return &Client{Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) ListDomains(ctx context.Context) ([]Domain, error) {
	var out []Domain
	seen := map[string]bool{}
	page := 1
	for page <= 100 {
		q := url.Values{"page": {fmt.Sprint(page)}, "limit": {"100"}}
		var resp struct {
			Page  int `json:"page"`
			Pager struct {
				Page  int `json:"page"`
				Pages int `json:"pages"`
			} `json:"pager"`
			Buckets []struct {
				Name    string `json:"bucket_name"`
				HTTPS   string `json:"https"`
				Domains []struct {
					Domain string `json:"domain"`
					Status string `json:"status"`
				} `json:"domains"`
			} `json:"buckets"`
		}
		if err := c.do(ctx, http.MethodGet, "/buckets?"+q.Encode(), nil, &resp); err != nil {
			return nil, err
		}
		for _, b := range resp.Buckets {
			for _, d := range b.Domains {
				if seen[d.Domain] {
					continue
				}
				seen[d.Domain] = true
				out = append(out, Domain{Bucket: b.Name, Domain: d.Domain, Status: d.Status, HTTPS: b.HTTPS})
			}
		}
		if len(resp.Buckets) == 0 || resp.Pager.Pages == 0 || page >= resp.Pager.Pages {
			break
		}
		page++
	}
	return out, nil
}

func (c *Client) ListCertificates(ctx context.Context, domain string) (map[string]Certificate, error) {
	out := map[string]Certificate{}
	since, max := "", ""
	for i := 0; i < 100; i++ {
		q := url.Values{"limit": {"100"}}
		if domain != "" {
			q.Set("domain", domain)
		}
		if since != "" {
			q.Set("since", since)
		}
		if max != "" {
			q.Set("max", max)
		}
		var resp struct {
			Result map[string]struct {
				CommonName string `json:"commonName"`
				Validity   struct {
					End int64 `json:"end"`
				} `json:"validity"`
				ConfigDomain int    `json:"config_domain"`
				Type         string `json:"crt_type"`
			} `json:"result"`
			Pager struct {
				Since string `json:"since"`
				Max   string `json:"max"`
			} `json:"pager"`
		}
		if err := c.do(ctx, http.MethodGet, "/https/certificate/list?"+q.Encode(), nil, &resp); err != nil {
			return nil, err
		}
		if len(resp.Result) == 0 {
			break
		}
		for id, v := range resp.Result {
			out[id] = Certificate{
				ID:         id,
				CommonName: v.CommonName,
				NotAfter:   time.UnixMilli(v.Validity.End),
				Configed:   v.ConfigDomain,
				Type:       v.Type,
			}
		}
		if resp.Pager.Max == "" || resp.Pager.Max == max {
			break
		}
		since, max = resp.Pager.Since, resp.Pager.Max
	}
	return out, nil
}

func (c *Client) Bindings(ctx context.Context, domain string) ([]Binding, error) {
	q := url.Values{"domain": {domain}}
	var resp struct {
		Status int `json:"status"`
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
	if err := c.do(ctx, http.MethodGet, "/https/services/manager?"+q.Encode(), nil, &resp); err != nil {
		return nil, err
	}
	out := make([]Binding, 0, len(resp.Result))
	for _, b := range resp.Result {
		out = append(out, Binding{
			CertID:      b.CertID,
			HTTPS:       b.HTTPS,
			ForceHTTPS:  b.ForceHTTPS,
			SourceHTTPS: b.SourceHTTPS,
			NotAfter:    time.UnixMilli(b.Validity.End),
		})
	}
	return out, nil
}

func (c *Client) UploadCertificate(ctx context.Context, certPEM, keyPEM, name string) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"certificate": certPEM,
		"private_key": keyPEM,
		"name":        name,
	})
	var resp struct {
		CertID string `json:"certificate_id"`
		Result struct {
			CertID string `json:"certificate_id"`
		} `json:"result"`
		Status  int    `json:"status"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, http.MethodPost, "/https/certificate", body, &resp); err != nil {
		return "", err
	}
	if resp.CertID == "" {
		resp.CertID = resp.Result.CertID
	}
	if resp.CertID == "" {
		return "", fmt.Errorf("upyun upload certificate: no certificate_id in response (status=%d message=%s)", resp.Status, resp.Message)
	}
	return resp.CertID, nil
}

func (c *Client) UpdateCertificate(ctx context.Context, certID, certPEM, keyPEM string) error {
	body, _ := json.Marshal(map[string]string{
		"certificate_id": certID,
		"certificate":    certPEM,
		"private_key":    keyPEM,
	})
	var resp struct {
		Status  int    `json:"status"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, http.MethodPut, "/https/certificate", body, &resp); err != nil {
		return err
	}
	if resp.Status != 0 {
		return fmt.Errorf("upyun update certificate %s: status=%d message=%s", certID, resp.Status, resp.Message)
	}
	return nil
}

// BindCertificate binds certID to domain. https enables CDN HTTPS.
func (c *Client) BindCertificate(ctx context.Context, domain, certID string, https, forceHTTPS, sourceHTTPS bool) error {
	body, _ := json.Marshal(map[string]any{
		"domain":         domain,
		"certificate_id": certID,
		"https":          https,
		"force_https":    forceHTTPS,
		"source_https":   sourceHTTPS,
	})
	var resp struct {
		Status  int    `json:"status"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, http.MethodPost, "/https/services/manager", body, &resp); err != nil {
		return err
	}
	if resp.Status != 0 {
		return fmt.Errorf("upyun bind %s: status=%d message=%s", domain, resp.Status, resp.Message)
	}
	return nil
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) error {
	var last error
	for attempt := range 3 {
		retry, err := c.doOnce(ctx, method, path, body, out)
		if err == nil {
			return nil
		}
		last = err
		if !retry {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 2 * time.Second):
		}
	}
	return last
}

func (c *Client) doOnce(ctx context.Context, method, path string, body []byte, out any) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, method, apiBase+path, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Type    string `json:"type"`
			Code    string `json:"error_code"`
			Message string `json:"message"`
			Field   string `json:"field"`
			Request string `json:"request"`
		}
		_ = json.Unmarshal(data, &e)
		return e.Code == "21000", fmt.Errorf("upyun %s %s: http %d: %s (%s) field=%s: %s", method, path, resp.StatusCode, e.Type, e.Code, e.Field, e.Message)
	}
	if out == nil {
		return false, nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return false, fmt.Errorf("upyun %s %s: decode: %w: %s", method, path, err, truncate(data, 300))
	}
	return false, nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
