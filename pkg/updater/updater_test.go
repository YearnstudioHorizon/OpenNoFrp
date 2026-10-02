package updater

import "testing"

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool
	}{
		{"v0.1.0", "v0.1.0", false},
		{"v0.1.0", "v0.2.0", true},
		{"0.1.0", "v0.1.0", false},
		{"0.1.0", "v0.2.0", true},
		{"dev", "v1.0.0", true},
	}

	for _, tt := range tests {
		got := compareVersions(tt.current, tt.latest)
		if got != tt.want {
			t.Errorf("compareVersions(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
		}
	}
}
