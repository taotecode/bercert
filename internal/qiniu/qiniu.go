package qiniu

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	apiHost    = "api.qiniu.com"
	fusionHost = "fusion.qiniuapi.com"
)

type Client struct {
	AK         string
	SK         string
	HTTP       *http.Client
	Now        func() time.Time
	APIBase    string
	FusionBase string
}

type Domain struct {
	Name       string    `json:"name"`
	Protocol   string    `json:"protocol"`
	GeoCover   string    `json:"geoCover"`
	Product    string    `json:"product"`
	Platform   string    `json:"platform"`
	CName      string    `json:"cname"`
	CreateAt   time.Time `json:"createAt"`
	ModifyAt   time.Time `json:"modifyAt"`
	HTTPS      HTTPSConf `json:"https"`
	FreezeType string    `json:"freezeType"`
}

type HTTPSConf struct {
	CertID      string   `json:"certId"`
	ForceHTTPS  bool     `json:"forceHttps"`
	HTTP2Enable bool     `json:"http2Enable"`
	TLSVersions []string `json:"tlsVersions"`
}

type Certificate struct {
	ID         string   `json:"certid"`
	Name       string   `json:"name"`
	CommonName string   `json:"common_name"`
	DNSNames   []string `json:"dnsnames"`
	NotBefore  int64    `json:"not_before"`
	NotAfter   int64    `json:"not_after"`
	CreateTime int64    `json:"create_time"`
}

func (c Certificate) ExpiresAt() time.Time { return time.Unix(c.NotAfter, 0) }

func New(ak, sk string) *Client {
	return &Client{
		AK:         ak,
		SK:         sk,
		HTTP:       &http.Client{Timeout: 30 * time.Second},
		Now:        time.Now,
		APIBase:    "https://" + apiHost,
		FusionBase: "https://" + fusionHost,
	}
}

func (c *Client) ListDomains(ctx context.Context) ([]Domain, error) {
	var out []Domain
	marker := ""
	for i := 0; i < 50; i++ {
		q := url.Values{}
		if marker != "" {
			q.Set("marker", marker)
		}
		q.Set("limit", "100")
		var resp struct {
			Domains []Domain `json:"domains"`
			Marker  string   `json:"marker"`
		}
		if err := c.do(ctx, http.MethodGet, c.APIBase, apiHost, "/domain?"+q.Encode(), nil, &resp); err != nil {
			return nil, err
		}
		out = append(out, resp.Domains...)
		if resp.Marker == "" || len(resp.Domains) == 0 {
			break
		}
		marker = resp.Marker
	}
	return out, nil
}

func (c *Client) GetDomain(ctx context.Context, name string) (*Domain, error) {
	var d Domain
	if err := c.do(ctx, http.MethodGet, c.APIBase, apiHost, "/domain/"+url.PathEscape(name), nil, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

func (c *Client) ListCertificates(ctx context.Context) ([]Certificate, error) {
	var out []Certificate
	marker := ""
	for i := 0; i < 100; i++ {
		q := url.Values{}
		q.Set("marker", marker)
		q.Set("limit", "100")
		var resp struct {
			Certs  []Certificate `json:"certs"`
			Marker string        `json:"marker"`
		}
		if err := c.do(ctx, http.MethodGet, c.FusionBase, fusionHost, "/sslcert?"+q.Encode(), nil, &resp); err != nil {
			return nil, err
		}
		out = append(out, resp.Certs...)
		if resp.Marker == "" || len(resp.Certs) == 0 {
			break
		}
		marker = resp.Marker
	}
	return out, nil
}

func (c *Client) GetCertificate(ctx context.Context, id string) (*Certificate, error) {
	var resp struct {
		Cert Certificate `json:"cert"`
	}
	if err := c.do(ctx, http.MethodGet, c.FusionBase, fusionHost, "/sslcert/"+url.PathEscape(id), nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Cert, nil
}

// UploadCertificate registers a certificate and returns its Qiniu cert ID.
func (c *Client) UploadCertificate(ctx context.Context, name, pri, ca string) (string, error) {
	body, _ := json.Marshal(map[string]string{"name": name, "pri": pri, "ca": ca})
	var resp struct {
		CertID string `json:"certID"`
		Code   int    `json:"code"`
		Error  string `json:"error"`
	}
	if err := c.do(ctx, http.MethodPost, c.FusionBase, fusionHost, "/sslcert", body, &resp); err != nil {
		return "", err
	}
	if resp.CertID == "" {
		return "", fmt.Errorf("qiniu upload certificate: code=%d error=%s", resp.Code, resp.Error)
	}
	return resp.CertID, nil
}

// BindCertificate enables HTTPS (sslize) or updates the certificate on an HTTPS domain.
func (c *Client) BindCertificate(ctx context.Context, d *Domain, certID string, forceHTTPS, http2 bool, tlsVersions string) error {
	payload := map[string]any{
		"certId":      certID,
		"forceHttps":  forceHTTPS,
		"http2Enable": http2,
	}
	if tlsVersions != "" {
		payload["tlsVersions"] = splitTLSVersions(tlsVersions)
	}
	body, _ := json.Marshal(payload)
	action := "httpsconf"
	if d.Protocol != "https" {
		action = "sslize"
	}
	var resp struct {
		Code  int    `json:"code"`
		Error string `json:"error"`
	}
	if err := c.do(ctx, http.MethodPut, c.APIBase, apiHost, fmt.Sprintf("/domain/%s/%s", url.PathEscape(d.Name), action), body, &resp); err != nil {
		return err
	}
	if resp.Code != 200 {
		return fmt.Errorf("qiniu %s %s: code=%d error=%s", action, d.Name, resp.Code, resp.Error)
	}
	return nil
}

func (c *Client) do(ctx context.Context, method, base, host, pathQuery string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, base+pathQuery, bytes.NewReader(body))
	if err != nil {
		return err
	}
	ts := c.Now().UTC().Format("20060102T150405Z")
	req.Header.Set("Authorization", c.authorization(method, host, pathQuery, body, ts))
	if host == apiHost {
		req.Header.Set("X-Qiniu-Date", ts)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("qiniu %s %s%s: http %d: %s", method, host, pathQuery, resp.StatusCode, truncate(data, 300))
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("qiniu %s %s%s: decode: %w: %s", method, host, pathQuery, err, truncate(data, 300))
	}
	return nil
}

func (c *Client) authorization(method, host, pathQuery string, body []byte, ts string) string {
	if host == fusionHost {
		data := pathQuery + "\n"
		return "QBox " + c.AK + ":" + urlsafeHMAC(data, c.SK)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", method, pathQuery)
	fmt.Fprintf(&b, "Host: %s\n", host)
	if body != nil {
		b.WriteString("Content-Type: application/json\n")
	}
	fmt.Fprintf(&b, "X-Qiniu-Date: %s\n", ts)
	b.WriteString("\n")
	b.Write(body)
	return "Qiniu " + c.AK + ":" + urlsafeHMAC(b.String(), c.SK)
}

func urlsafeHMAC(data, key string) string {
	m := hmac.New(sha1.New, []byte(key))
	m.Write([]byte(data))
	return base64.URLEncoding.EncodeToString(m.Sum(nil))
}

// splitTLSVersions accepts "TLSv1.1/TLSv1.2" or a comma-separated list.
// The real API rejects a bare string: tlsVersions must be a JSON array.
func splitTLSVersions(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == ',' || r == ' ' })
	out := make([]string, 0, len(f))
	for _, v := range f {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
