package panel

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/taotecode/bercert/internal/certutil"
)

type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
	Now     func() time.Time
}

type Certificate struct {
	ID            int       `json:"id"`
	PrimaryDomain string    `json:"primaryDomain"`
	PEM           string    `json:"pem"`
	PrivateKey    string    `json:"privateKey"`
	Domains       string    `json:"domains"`
	ExpireDate    time.Time `json:"expireDate"`
	StartDate     time.Time `json:"startDate"`
	Status        string    `json:"status"`
	Message       string    `json:"message"`
	Type          string    `json:"type"`
	Provider      string    `json:"provider"`
	Organization  string    `json:"organization"`
	AcmeAccountID uint      `json:"acmeAccountId"`
	DNSAccountID  uint      `json:"dnsAccountId"`
	KeyType       string    `json:"keyType"`
	AutoRenew     bool      `json:"autoRenew"`
	LogPath       string    `json:"logPath"`
}

type ACMEAccount struct {
	ID      uint   `json:"id"`
	Email   string `json:"email"`
	Type    string `json:"type"`
	KeyType string `json:"keyType"`
}

type DNSAccount struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type CreateCertificateRequest struct {
	PrimaryDomain string `json:"primaryDomain"`
	OtherDomains  string `json:"otherDomains,omitempty"`
	Provider      string `json:"provider"`
	AcmeAccountID uint   `json:"acmeAccountId"`
	DNSAccountID  uint   `json:"dnsAccountId,omitempty"`
	AutoRenew     bool   `json:"autoRenew"`
	KeyType       string `json:"keyType"`
	Description   string `json:"description,omitempty"`
}

func New(baseURL, apiKey string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		Now:     time.Now,
	}
}

func (c *Client) ListCertificates(ctx context.Context) ([]Certificate, error) {
	var all []Certificate
	page := 1
	for {
		var resp struct {
			Code int `json:"code"`
			Data struct {
				Total int           `json:"total"`
				Items []Certificate `json:"items"`
			} `json:"data"`
		}
		body, _ := json.Marshal(map[string]any{"page": page, "pageSize": 100})
		if err := c.do(ctx, http.MethodPost, "/api/v2/websites/ssl/search", body, &resp); err != nil {
			return nil, err
		}
		if resp.Data.Total == 0 || len(resp.Data.Items) == 0 {
			break
		}
		all = append(all, resp.Data.Items...)
		if len(all) >= resp.Data.Total {
			break
		}
		page++
		if page > 100 {
			return nil, fmt.Errorf("certificate pagination exceeded 100 pages")
		}
	}
	return all, nil
}

func (c *Client) GetCertificate(ctx context.Context, id int) (*Certificate, error) {
	var resp struct {
		Code int         `json:"code"`
		Data Certificate `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/v2/websites/ssl/%d", id), nil, &resp); err != nil {
		return nil, err
	}
	if resp.Code != 200 {
		return nil, fmt.Errorf("1panel certificate %d: code=%d", id, resp.Code)
	}
	return &resp.Data, nil
}

func (c *Client) SearchACMEAccounts(ctx context.Context) ([]ACMEAccount, error) {
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Items []ACMEAccount `json:"items"`
		} `json:"data"`
	}
	body, _ := json.Marshal(map[string]any{"page": 1, "pageSize": 100})
	if err := c.do(ctx, http.MethodPost, "/api/v2/websites/acme/search", body, &resp); err != nil {
		return nil, err
	}
	if resp.Code != 200 {
		return nil, fmt.Errorf("1panel acme accounts: code=%d", resp.Code)
	}
	return resp.Data.Items, nil
}

func (c *Client) SearchDNSAccounts(ctx context.Context) ([]DNSAccount, error) {
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Items []DNSAccount `json:"items"`
		} `json:"data"`
	}
	body, _ := json.Marshal(map[string]any{"page": 1, "pageSize": 100})
	if err := c.do(ctx, http.MethodPost, "/api/v2/websites/dns/search", body, &resp); err != nil {
		return nil, err
	}
	if resp.Code != 200 {
		return nil, fmt.Errorf("1panel dns accounts: code=%d", resp.Code)
	}
	return resp.Data.Items, nil
}

// CreateCertificate creates the record. 1Panel starts the ACME order asynchronously.
func (c *Client) CreateCertificate(ctx context.Context, req CreateCertificateRequest) (int, error) {
	var resp struct {
		Code int `json:"code"`
		Data struct {
			ID int `json:"id"`
		} `json:"data"`
	}
	body, _ := json.Marshal(req)
	if err := c.do(ctx, http.MethodPost, "/api/v2/websites/ssl", body, &resp); err != nil {
		return 0, err
	}
	if resp.Code != 200 || resp.Data.ID == 0 {
		return 0, fmt.Errorf("1panel create certificate: code=%d", resp.Code)
	}
	return resp.Data.ID, nil
}

// ObtainCertificate triggers (or retries) issuance for an existing certificate record.
func (c *Client) ObtainCertificate(ctx context.Context, id int) error {
	var resp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	body, _ := json.Marshal(map[string]any{"ID": id})
	if err := c.do(ctx, http.MethodPost, "/api/v2/websites/ssl/obtain", body, &resp); err != nil {
		return err
	}
	if resp.Code != 200 {
		return fmt.Errorf("1panel obtain certificate %d: code=%d %s", id, resp.Code, resp.Message)
	}
	return nil
}

// Find returns the best unused, still-valid certificate from 1Panel that covers domain.
func Find(certs []Certificate, domain string, now time.Time) *Certificate {
	domain = certutil.NormalizeDomain(domain)
	var best *Certificate
	bestScore := -1
	var bestNotAfter time.Time
	for i := range certs {
		ct := &certs[i]
		if ct.PEM == "" || ct.PrivateKey == "" {
			continue
		}
		leaf, err := certutil.Leaf(ct.PEM)
		if err != nil || now.After(leaf.NotAfter) || now.Before(leaf.NotBefore) {
			continue
		}
		names := append([]string(nil), leaf.DNSNames...)
		names = append(names, strings.Split(ct.Domains, ",")...)
		score := 0
		for _, n := range names {
			if s := certutil.Specificity(strings.TrimSpace(n), domain); s > score {
				score = s
			}
		}
		if score <= 0 {
			continue
		}
		if best == nil || score > bestScore || (score == bestScore && leaf.NotAfter.After(bestNotAfter)) {
			best = ct
			bestScore = score
			bestNotAfter = leaf.NotAfter
		}
	}
	return best
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(c.Now().Unix(), 10)
	h := md5.Sum([]byte("1panel" + c.APIKey + ts))
	req.Header.Set("1Panel-Token", hex.EncodeToString(h[:]))
	req.Header.Set("1Panel-Timestamp", ts)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("1panel %s %s: http %d: %s", method, path, resp.StatusCode, truncate(data, 200))
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("1panel %s %s: decode: %w: %s", method, path, err, truncate(data, 200))
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
