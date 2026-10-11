package panel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"opennofrp/server/internal/store"
)

const captchaCookie = "onfr_captcha"

type captchaChallenge struct {
	Answer  string
	Expires time.Time
}

// Only public settings may reach the login page.
type captchaPublic struct{ Provider, FCaptchaURL, SiteKey, GeetestID string }

func (p *Panel) renderLogin(w http.ResponseWriter, r *http.Request, message string) {
	w.Header().Set("Cache-Control", "no-store")
	s, err := p.Store.CaptchaSettings(r.Context())
	if err != nil {
		http.Error(w, "无法读取验证配置，请稍后重试", http.StatusServiceUnavailable)
		return
	}
	p.tmpl.ExecuteTemplate(w, "login.html", map[string]any{"Error": message, "Captcha": captchaPublic{s.Provider, s.FCaptchaURL, s.FCaptchaSiteKey, s.GeetestID}})
}

func (p *Panel) handleSecurityGet(w http.ResponseWriter, r *http.Request) {
	s, err := p.Store.CaptchaSettings(r.Context())
	if err != nil {
		http.Error(w, "无法读取验证配置", http.StatusInternalServerError)
		return
	}
	data := map[string]any{"Page": "security", "PageTitle": "安全设置", "CSRF": csrfFrom(r), "Settings": captchaPublic{s.Provider, s.FCaptchaURL, s.FCaptchaSiteKey, s.GeetestID}, "HasFCaptchaSecret": s.FCaptchaSecret != "", "HasGeetestKey": s.GeetestKey != "", "Error": r.URL.Query().Get("err"), "Notice": r.URL.Query().Get("ok")}
	w.Header().Set("Cache-Control", "no-store")
	p.tmpl.ExecuteTemplate(w, "security.html", data)
}

func validateCaptchaSettings(s store.CaptchaSettings) error {
	switch s.Provider {
	case "none", "builtin":
		return nil
	case "fcaptcha":
		u, err := url.Parse(s.FCaptchaURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("fCaptcha 实例地址必须是 HTTP 或 HTTPS 地址，不能包含用户名、查询参数或片段")
		}
		if s.FCaptchaSiteKey == "" || s.FCaptchaSecret == "" {
			return errors.New("请填写 fCaptcha Site Key 和 Secret")
		}
	case "geetest":
		if s.GeetestID == "" || s.GeetestKey == "" {
			return errors.New("请填写 GEETEST Captcha ID 和 Captcha Key")
		}
	default:
		return errors.New("不支持的验证方式")
	}
	return nil
}

func (p *Panel) handleCaptchaSettings(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "设置请求无效", http.StatusBadRequest)
		return
	}
	s, err := p.Store.CaptchaSettings(r.Context())
	if err != nil {
		http.Error(w, "无法读取验证配置", http.StatusInternalServerError)
		return
	}
	s.Provider = r.FormValue("provider")
	if r.Form.Has("fcaptcha_url") {
		s.FCaptchaURL = strings.TrimRight(strings.TrimSpace(r.FormValue("fcaptcha_url")), "/")
	}
	if r.Form.Has("fcaptcha_site_key") {
		s.FCaptchaSiteKey = strings.TrimSpace(r.FormValue("fcaptcha_site_key"))
	}
	if r.Form.Has("geetest_id") {
		s.GeetestID = strings.TrimSpace(r.FormValue("geetest_id"))
	}
	if secret := strings.TrimSpace(r.FormValue("fcaptcha_secret")); secret != "" {
		s.FCaptchaSecret = secret
	}
	if secret := strings.TrimSpace(r.FormValue("geetest_key")); secret != "" {
		s.GeetestKey = secret
	}
	if err := validateCaptchaSettings(s); err != nil {
		http.Redirect(w, r, "/security?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	if err := p.Store.SaveCaptchaSettings(r.Context(), s); err != nil {
		http.Error(w, "无法保存验证配置", http.StatusInternalServerError)
		return
	}
	p.mu.Lock()
	clear(p.captchaChallenges)
	p.mu.Unlock()
	http.Redirect(w, r, "/security?ok="+url.QueryEscape("人机验证设置已保存，下次登录生效"), http.StatusSeeOther)
}

// verifyCaptcha runs before checking credentials. Network and decoding errors fail closed.
func (p *Panel) verifyCaptcha(r *http.Request) error {
	s, err := p.Store.CaptchaSettings(r.Context())
	if err != nil {
		return err
	}
	if err := validateCaptchaSettings(s); err != nil {
		return err
	}
	switch s.Provider {
	case "none":
		return nil
	case "builtin":
		cookie, err := r.Cookie(captchaCookie)
		if err != nil {
			return err
		}
		p.mu.Lock()
		challenge, ok := p.captchaChallenges[cookie.Value]
		delete(p.captchaChallenges, cookie.Value)
		p.mu.Unlock()
		if !ok || !time.Now().Before(challenge.Expires) || subtle.ConstantTimeCompare([]byte(challenge.Answer), []byte(strings.TrimSpace(r.FormValue("captcha_answer")))) != 1 {
			return errors.New("invalid captcha")
		}
		return nil
	case "fcaptcha":
		token := r.FormValue("captcha_token")
		if token == "" {
			return errors.New("missing token")
		}
		if err := p.consumeExternalCaptcha("fcaptcha:"+s.FCaptchaURL+":"+s.FCaptchaSiteKey, token); err != nil {
			return err
		}
		body, _ := json.Marshal(map[string]string{"token": token, "secret": s.FCaptchaSecret})
		var result struct {
			Valid    bool     `json:"valid"`
			Score    *float64 `json:"score"`
			SiteKey  string   `json:"site_key"`
			Hostname string   `json:"hostname"`
			Action   string   `json:"action"`
		}
		if err := p.captchaRequest(r, s.FCaptchaURL+"/api/token/verify", "application/json", string(body), &result); err != nil {
			return err
		}
		if !result.Valid || result.Score == nil || *result.Score < 0 || *result.Score >= 0.5 {
			return errors.New("invalid captcha")
		}
		expectedHost := r.Host
		if p.BaseURL != "" {
			expectedHost = p.BaseURL
		} else {
			expectedHost = "//" + expectedHost
		}
		u, err := url.Parse(expectedHost)
		if err != nil || u.Hostname() == "" || !strings.EqualFold(strings.TrimSuffix(result.Hostname, "."), strings.TrimSuffix(u.Hostname(), ".")) || result.SiteKey != s.FCaptchaSiteKey || result.Action != "" {
			return errors.New("captcha site mismatch")
		}
		return nil
	case "geetest":
		values := url.Values{"captcha_id": {s.GeetestID}}
		for _, name := range []string{"lot_number", "captcha_output", "pass_token", "gen_time"} {
			value := r.FormValue(name)
			if value == "" {
				return fmt.Errorf("missing %s", name)
			}
			values.Set(name, value)
		}
		if err := p.consumeExternalCaptcha("geetest:"+s.GeetestID, values.Get("lot_number")); err != nil {
			return err
		}
		mac := hmac.New(sha256.New, []byte(s.GeetestKey))
		mac.Write([]byte(values.Get("lot_number")))
		values.Set("sign_token", hex.EncodeToString(mac.Sum(nil)))
		var result struct {
			Result string `json:"result"`
		}
		if err := p.captchaRequest(r, "https://gcaptcha4.geetest.com/validate?captcha_id="+url.QueryEscape(s.GeetestID), "application/x-www-form-urlencoded", values.Encode(), &result); err != nil {
			return err
		}
		if result.Result != "success" {
			return errors.New("invalid captcha")
		}
		return nil
	}
	return errors.New("unsupported captcha provider")
}

// Reserve tokens atomically before making the remote request, including failed
// attempts, so concurrent login requests cannot reuse a successful challenge.
func (p *Panel) consumeExternalCaptcha(provider, token string) error {
	key := hashSessionToken(provider + ":" + token)
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, expires := range p.captchaUsed {
		if !now.Before(expires) {
			delete(p.captchaUsed, key)
		}
	}
	if _, ok := p.captchaUsed[key]; ok {
		return errors.New("captcha already used")
	}
	if len(p.captchaUsed) >= 4096 {
		return errors.New("captcha capacity reached")
	}
	p.captchaUsed[key] = now.Add(15 * time.Minute)
	return nil
}

func (p *Panel) captchaRequest(r *http.Request, endpoint, contentType, body string, result any) error {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := p.captchaHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("captcha status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10+1))
	if err != nil || len(data) > 64<<10 {
		return errors.New("invalid captcha response")
	}
	return json.Unmarshal(data, result)
}

func captchaRand(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(err)
	}
	return int(n.Int64())
}

// Bitmap digits avoid a font dependency and keep the built-in CAPTCHA offline.
var captchaDigits = []string{
	"01110100011001110101110011000101110", "00100011000010000100001000010001110",
	"01110100010000100010001000100011111", "11110000010000101110000010000111110",
	"00010001100101010010111110001000010", "11111100001000011110000010000111110",
	"01110100001000011110100011000101110", "11111000010001000100010000100001000",
	"01110100011000101110100011000101110", "01110100011000101111000010000101110",
}

func (p *Panel) handleCaptchaImage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	s, err := p.Store.CaptchaSettings(r.Context())
	if err != nil {
		http.Error(w, "验证服务不可用", http.StatusServiceUnavailable)
		return
	}
	if s.Provider != "builtin" {
		http.NotFound(w, r)
		return
	}
	now := time.Now()
	p.mu.Lock()
	for key, value := range p.captchaChallenges {
		if !now.Before(value.Expires) {
			delete(p.captchaChallenges, key)
		}
	}
	if cookie, err := r.Cookie(captchaCookie); err == nil {
		delete(p.captchaChallenges, cookie.Value)
	}
	if len(p.captchaChallenges) >= 2048 {
		p.mu.Unlock()
		http.Error(w, "请稍后重试", http.StatusTooManyRequests)
		return
	}
	answer := ""
	for i := 0; i < 5; i++ {
		answer += string('0' + byte(captchaRand(10)))
	}
	id := randomHex(32)
	p.captchaChallenges[id] = captchaChallenge{answer, now.Add(3 * time.Minute)}
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: captchaCookie, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil, MaxAge: 180})
	img := image.NewRGBA(image.Rect(0, 0, 200, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 200; x++ {
			img.Set(x, y, color.RGBA{245, 247, 251, 255})
		}
	}
	for i := 0; i < 400; i++ {
		img.Set(captchaRand(200), captchaRand(64), color.RGBA{160, 180, 210, 255})
	}
	for i, digit := range answer {
		x0, y0 := 12+i*36+captchaRand(6), 10+captchaRand(10)
		ink := color.RGBA{uint8(30 + captchaRand(50)), uint8(40 + captchaRand(50)), uint8(80 + captchaRand(60)), 255}
		for j, bit := range captchaDigits[digit-'0'] {
			if bit == '1' {
				for dy := 0; dy < 5; dy++ {
					for dx := 0; dx < 5; dx++ {
						img.Set(x0+j%5*5+dx, y0+j/5*5+dy, ink)
					}
				}
			}
		}
	}
	w.Header().Set("Content-Type", "image/png")
	png.Encode(w, img)
}
