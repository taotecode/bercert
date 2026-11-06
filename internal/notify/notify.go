package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Enabled       bool
	FeishuWebhook string
	FeishuSecret  string
	WeComWebhook  string

	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string
	SMTPTo       string
	SMTPTLS      string

	StateFile string
}

type Event struct {
	Provider   string `json:"provider"`
	Domain     string `json:"domain"`
	Decision   string `json:"decision"`
	Reason     string `json:"reason"`
	CertID     string `json:"cert_id,omitempty"`
	CertExpiry string `json:"cert_expiry,omitempty"`
	Prepared   bool   `json:"prepared"`
	Error      string `json:"error,omitempty"`
}

type Notifier struct {
	cfg   Config
	http  *http.Client
	state map[string]string
}

func New(cfg Config) *Notifier {
	return &Notifier{
		cfg:   cfg,
		http:  &http.Client{Timeout: 15 * time.Second},
		state: loadState(cfg.StateFile),
	}
}

func (n *Notifier) Enabled() bool {
	return n.cfg.Enabled && (n.cfg.FeishuWebhook != "" || n.cfg.WeComWebhook != "" || n.cfg.SMTPHost != "")
}

// Send notifies once per unresolved (provider, domain, reason, certificate)
// condition. Resolved domains are dropped from the state file.
func (n *Notifier) Send(ctx context.Context, events []Event) (int, error) {
	if !n.Enabled() {
		return 0, nil
	}

	wanted := make([]Event, 0, len(events))
	current := make(map[string]string, len(events))
	for _, e := range events {
		if !needsNotify(e) {
			continue
		}
		key := e.Provider + "|" + e.Domain
		fp := fingerprint(e)
		current[key] = fp
		if n.state[key] == fp {
			continue
		}
		wanted = append(wanted, e)
	}
	if len(wanted) == 0 {
		n.prune(current)
		return 0, nil
	}

	text := n.batchText(wanted)
	var errs []string
	sent := 0
	if n.cfg.FeishuWebhook != "" {
		if err := n.sendFeishu(ctx, text); err != nil {
			errs = append(errs, "feishu: "+err.Error())
		} else {
			sent++
		}
	}
	if n.cfg.WeComWebhook != "" {
		if err := n.sendWeCom(ctx, text); err != nil {
			errs = append(errs, "wecom: "+err.Error())
		} else {
			sent++
		}
	}
	if n.cfg.SMTPHost != "" {
		if err := n.sendMail(text); err != nil {
			errs = append(errs, "email: "+err.Error())
		} else {
			sent++
		}
	}
	if sent == 0 {
		return 0, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	n.state = current
	if err := saveState(n.cfg.StateFile, n.state); err != nil {
		errs = append(errs, "save state: "+err.Error())
	}
	if len(errs) > 0 {
		return sent, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return sent, nil
}

func needsNotify(e Event) bool {
	if e.Error != "" {
		return true
	}
	switch e.Decision {
	case "manual", "no-cert", "invalid":
		return true
	}
	return false
}

func fingerprint(e Event) string {
	return strings.Join([]string{e.Decision, e.Error, e.Reason, e.CertID, e.CertExpiry}, "|")
}

func (n *Notifier) prune(current map[string]string) {
	if len(n.state) == len(current) {
		unchanged := true
		for k, v := range current {
			if n.state[k] != v {
				unchanged = false
				break
			}
		}
		if unchanged {
			return
		}
	}
	n.state = current
	_ = saveState(n.cfg.StateFile, n.state)
}

func (n *Notifier) batchText(events []Event) string {
	var b strings.Builder
	fmt.Fprintf(&b, "【bercert 需要人工处理】%d 个域名\n", len(events))
	for i, e := range events {
		if i > 0 {
			b.WriteString("\n— — —\n")
		}
		b.WriteString(eventText(e))
	}
	fmt.Fprintf(&b, "\n时间：%s", time.Now().Format("2006-01-02 15:04:05 MST"))
	return b.String()
}

func eventText(e Event) string {
	var b strings.Builder
	fmt.Fprintf(&b, "域名：%s\n服务商：%s\n状态：%s\n", e.Domain, e.Provider, e.Decision)
	if e.Error != "" {
		fmt.Fprintf(&b, "错误：%s\n", e.Error)
	}
	if e.CertID != "" {
		fmt.Fprintf(&b, "证书：%s", e.CertID)
		if e.CertExpiry != "" {
			fmt.Fprintf(&b, "（到期 %s）", e.CertExpiry)
		}
		if e.Prepared {
			b.WriteString("，已上传/绑定")
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "原因：%s\n", e.Reason)
	fmt.Fprintf(&b, "建议操作：%s\n", instructions(e.Provider, e.Decision))
	return b.String()
}

func instructions(provider, decision string) string {
	if decision == "no-cert" {
		return "在 1Panel 为该域名签发一张覆盖它的证书，然后重新运行 bercert renew。"
	}
	switch provider {
	case "upyun":
		return "登录 https://console.upyun.com/ → 服务管理 → 对应空间 → 功能配置 → HTTPS，开通/购买“自主域名 HTTPS 服务”，并确认该域名 HTTPS 访问已开启。证书已由程序上传，无需重复上传。"
	case "qiniu":
		return "登录七牛云控制台 → 域名管理，检查该域名的 HTTPS 配置和证书绑定状态。"
	default:
		return "请在对应服务商控制台检查该域名的 HTTPS 配置。"
	}
}

func (n *Notifier) sendFeishu(ctx context.Context, text string) error {
	payload := map[string]any{"msg_type": "text", "content": map[string]string{"text": text}}
	if n.cfg.FeishuSecret != "" {
		ts := time.Now().Unix()
		payload["timestamp"] = strconv.FormatInt(ts, 10)
		payload["sign"] = feishuSign(n.cfg.FeishuSecret, ts)
	}
	return n.postJSON(ctx, n.cfg.FeishuWebhook, payload)
}

func feishuSign(secret string, ts int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d\n%s", ts, secret)))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func (n *Notifier) sendWeCom(ctx context.Context, text string) error {
	return n.postJSON(ctx, n.cfg.WeComWebhook, map[string]any{
		"msgtype": "text",
		"text":    map[string]string{"content": text},
	})
}

func (n *Notifier) postJSON(ctx context.Context, url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("http %d: %s", resp.StatusCode, truncate(data, 200))
	}
	var result struct {
		Code    int    `json:"code"`
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
		Msg     string `json:"msg"`
	}
	_ = json.Unmarshal(data, &result)
	if result.Code != 0 || result.ErrCode != 0 {
		return fmt.Errorf("%s%s%s", result.Msg, result.ErrMsg, truncate(data, 200))
	}
	return nil
}

func (n *Notifier) sendMail(text string) error {
	to := splitMail(n.cfg.SMTPTo)
	if len(to) == 0 {
		return fmt.Errorf("SMTP_TO is empty")
	}
	from := n.cfg.SMTPFrom
	if from == "" {
		from = n.cfg.SMTPUsername
	}
	if from == "" {
		return fmt.Errorf("SMTP_FROM is empty")
	}
	subject := "bercert: certificate needs manual action"
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n",
		from, strings.Join(to, ", "), subject, text)

	addr := net.JoinHostPort(n.cfg.SMTPHost, strconv.Itoa(n.cfg.SMTPPort))
	mode := strings.ToLower(n.cfg.SMTPTLS)
	if mode == "" {
		mode = "implicit"
	}

	var (
		client *smtp.Client
		err    error
	)
	if mode == "implicit" {
		conn, derr := tls.Dial("tcp", addr, &tls.Config{ServerName: n.cfg.SMTPHost})
		if derr != nil {
			return derr
		}
		client, err = smtp.NewClient(conn, n.cfg.SMTPHost)
	} else {
		client, err = smtp.Dial(addr)
	}
	if err != nil {
		return err
	}
	defer client.Close()

	if mode == "starttls" {
		if err := client.StartTLS(&tls.Config{ServerName: n.cfg.SMTPHost}); err != nil {
			return err
		}
	}
	if n.cfg.SMTPUsername != "" {
		if err := client.Auth(smtp.PlainAuth("", n.cfg.SMTPUsername, n.cfg.SMTPPassword, n.cfg.SMTPHost)); err != nil {
			return err
		}
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func splitMail(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func loadState(path string) map[string]string {
	out := map[string]string{}
	if path == "" {
		return out
	}
	data, err := os.ReadFile(path)
	if err == nil {
		_ = json.Unmarshal(data, &out)
	}
	return out
}

func saveState(path string, state map[string]string) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
