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
  "api":{"source_url":"http://172.31.255.1:18080/v1/networks","token":"01234567890123456789012345678901","allow_insecure_http":true},
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
	data := `{"role":"agent","state_file":"/tmp/netflix-pbrd.state","api":{"source_url":"http://127.0.0.1:18080/v1/networks","token":"01234567890123456789012345678901","allow_insecure_http":true},"apply":[{"driver":"linux-edge","interface":"wg-relay","peer":"peer-key"}]}`
	if err := ioutil.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "source_net") {
		t.Fatalf("expected source_net validation error, got %v", err)
	}
}

func TestAllowedUsesFullTunnelWithoutRedundantNetworks(t *testing.T) {
	c := ApplyConfig{BaseAllowed: []string{"0.0.0.0/0"}}
	if got := allowed(c, []string{"45.57.22.0/24"}); got != "0.0.0.0/0" {
		t.Fatalf("got %q", got)
	}
}
