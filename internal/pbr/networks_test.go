package pbr

import (
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"
)

func TestMergeCanonicalizesAndFilters(t *testing.T) {
	got := Merge([]string{"98.85.45.78", "98.85.45.78/32", "23.23.189.145/28", "192.168.1.1", "bad"})
	want := []string{"23.23.189.144/28", "98.85.45.78/32"}
	if !Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestPollInterval(t *testing.T) {
	if _, err := (Config{Interval: "1s"}).PollInterval(); err == nil {
		t.Fatal("expected short interval error")
	}
	if got, err := (Config{}).PollInterval(); err != nil || got.String() != "30s" {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestLinuxEdgeAllowsDirectInterfaceRoutes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{
  "role":"agent",
  "state_file":"/tmp/netflix-pbrd.state",
  "api":{"source_url":"http://172.31.255.1:18080/v1/networks","token":"01234567890123456789012345678901","report_token":"abcdefghijklmnopqrstuvwxyz012345","allow_insecure_http":true},
  "apply":[{"driver":"linux-edge","interface":"wg-relay","peer":"peer-key","source_net":"192.168.8.0/24"}]
}`
	if err := ioutil.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("direct interface route config rejected: %v", err)
	}
}

func TestLinuxEdgeStillValidatesRequiredFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{"role":"agent","state_file":"/tmp/netflix-pbrd.state","api":{"source_url":"http://127.0.0.1:18080/v1/networks","token":"01234567890123456789012345678901","report_token":"abcdefghijklmnopqrstuvwxyz012345","allow_insecure_http":true},"apply":[{"driver":"linux-edge","interface":"wg-relay","peer":"peer-key"}]}`
	if err := ioutil.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "source_net") {
		t.Fatalf("expected source_net validation error, got %v", err)
	}
}

func TestCanonicalNetworkRejectsBroadAndPrivateRanges(t *testing.T) {
	for _, value := range []string{"8.8.8.8/0", "23.1.2.3/8", "192.168.1.1/32", "10.0.0.0/24", "100.64.0.1/32", "198.51.100.1/32"} {
		if got, ok := CanonicalNetwork(value); ok {
			t.Fatalf("CanonicalNetwork(%q) unexpectedly accepted as %q", value, got)
		}
	}
}

func TestValidateAgentReportsHostsOnlyAndEnforcesLimit(t *testing.T) {
	if _, err := ValidateNetworks([]string{"23.23.189.144/28"}, true, 10); err == nil {
		t.Fatal("expected non-host report rejection")
	}
	if _, err := ValidateNetworks([]string{"98.85.45.78", "54.84.54.3"}, true, 1); err == nil {
		t.Fatal("expected network limit rejection")
	}
}

func TestAllowedUsesFullTunnelWithoutRedundantNetworks(t *testing.T) {
	c := ApplyConfig{BaseAllowed: []string{"0.0.0.0/0"}}
	if got := allowed(c, []string{"45.57.22.0/24"}); got != "0.0.0.0/0" {
		t.Fatalf("got %q", got)
	}
}

func TestConfigRequiresSeparateReportToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{"role":"controller","state_file":"/tmp/state","api":{"listen":"127.0.0.1:18080","token":"01234567890123456789012345678901","report_token":"01234567890123456789012345678901","allow_insecure_http":true},"discovery":{"domains":["example.com"]}}`
	if err := ioutil.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("got %v", err)
	}
}

func TestConfigRejectsUnsafeCommandFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{"role":"agent","state_file":"/tmp/state","api":{"source_url":"http://127.0.0.1/v1/networks","token":"01234567890123456789012345678901","report_token":"abcdefghijklmnopqrstuvwxyz012345","allow_insecure_http":true},"apply":[{"driver":"linux-edge","interface":"wg0\nroute flush table main","peer":"peer","source_net":"192.168.8.0/24"}]}`
	if err := ioutil.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "invalid interface") {
		t.Fatalf("got %v", err)
	}
}

func TestConfigAcceptsLearningControllerWithoutBootstrapDomains(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{"role":"controller","state_file":"/tmp/state","api":{"listen":"127.0.0.1:18080","token":"01234567890123456789012345678901","report_token":"abcdefghijklmnopqrstuvwxyz012345","allow_insecure_http":true},"dns_proxy":{"listen":"127.0.0.1:1053","upstream":"127.0.0.1:53"}}`
	if err := ioutil.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatal(err)
	}
}

func TestConfigRejectsIncompleteDNSProxy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{"role":"controller","state_file":"/tmp/state","api":{"listen":"127.0.0.1:18080","token":"01234567890123456789012345678901","report_token":"abcdefghijklmnopqrstuvwxyz012345","allow_insecure_http":true},"dns_proxy":{"listen":"127.0.0.1:1053"}}`
	if err := ioutil.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "dns_proxy") {
		t.Fatalf("got %v", err)
	}
}
