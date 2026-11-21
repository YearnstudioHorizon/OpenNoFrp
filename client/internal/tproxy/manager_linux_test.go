//go:build linux

package tproxy

import (
	"os"
	"strings"
	"testing"
)

// Exercise the production iproute2, iptables and sysctl paths in a disposable
// namespace. Ordinary go test runs never change host networking.
func TestRuntimeSetupAndRecoveryInNamespace(t *testing.T) {
	if os.Getenv("OPENNOFRP_TEST_NETNS") != "1" {
		t.Skip("requires a disposable Linux network namespace")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	host, err := os.Readlink("/proc/1/ns/net")
	if err != nil || current == host {
		t.Fatalf("network namespace isolation required: %v", err)
	}
	if _, err := runIP("link", "set", "lo", "up"); err != nil {
		t.Fatal(err)
	}
	settings := requiredSysctls("lo")
	before := make(map[string]string)
	for _, setting := range settings {
		value, err := readSysctl(setting.Name)
		if err != nil {
			t.Fatal(err)
		}
		before[setting.Name] = value
	}

	m := Manager{StateDir: t.TempDir()}
	if err := m.SetupRuntime("lo", DefaultRouteTable, DefaultFWMark); err != nil {
		t.Fatal(err)
	}
	for _, guard := range loopbackGuards() {
		if !ruleExists(guard.Table, guard.Chain, guard.Args...) {
			t.Fatalf("missing %s/%s loopback guard", guard.Table, guard.Chain)
		}
	}
	// Another program may install an entry after setup. Cleanup must preserve it.
	if _, err := runIP("route", "add", "192.0.2.0/24", "dev", "lo", "table", "42141"); err != nil {
		t.Fatal(err)
	}
	if err := (Manager{StateDir: m.StateDir}).Teardown(); err != nil {
		t.Fatal(err)
	}
	routes, err := routesInTable(DefaultRouteTable)
	if err != nil || !strings.Contains(routes, "192.0.2.0/24") || strings.Contains(routes, "local default") {
		t.Fatalf("incorrect route recovery: %q, %v", routes, err)
	}
	for _, setting := range settings {
		value, err := readSysctl(setting.Name)
		if err != nil || value != before[setting.Name] {
			t.Fatalf("did not restore %s: %q, %v", setting.Name, value, err)
		}
	}
	for _, guard := range loopbackGuards() {
		if ruleExists(guard.Table, guard.Chain, guard.Args...) {
			t.Fatalf("leftover %s/%s loopback guard", guard.Table, guard.Chain)
		}
	}
}
