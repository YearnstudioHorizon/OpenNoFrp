package tempvpn

// Config is a short-lived access credential exported once from the panel.
type Config struct {
	Server      string `json:"server"`
	Fingerprint string `json:"fingerprint"`
	Token       string `json:"token"`
	ExpiresAt   int64  `json:"expires_at"`
}
