package config

import "testing"

func TestTCPResourceDefaultsAndValidation(t *testing.T) {
	var cfg Config
	applyDefaults(&cfg)
	if cfg.Server.MaxTCPConnections != 512 || cfg.Server.TCPIdleTimeoutSeconds != 300 {
		t.Fatalf("unexpected defaults: %+v", cfg.Server)
	}
	if err := validate(&cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Server.MaxTCPConnections = -1
	if validate(&cfg) == nil {
		t.Fatal("negative TCP connection limit accepted")
	}
	cfg.Server.MaxTCPConnections = 512
	cfg.Server.TCPIdleTimeoutSeconds = -1
	if validate(&cfg) == nil {
		t.Fatal("negative TCP idle timeout accepted")
	}
}
