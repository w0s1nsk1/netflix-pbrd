package pbr

import (
	"context"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestGenerateNestedBundleCreatesMatchingSecureConfigs(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := GenerateNestedBundle(NestedBundleOptions{OutputDir: dir, EdgePeer: "exit-public-key"}); err != nil {
		t.Fatal(err)
	}
	edge, err := LoadConfig(filepath.Join(dir, "edge.json"))
	if err != nil {
		t.Fatal(err)
	}
	exit, err := LoadConfig(filepath.Join(dir, "exit.json"))
	if err != nil {
		t.Fatal(err)
	}
	if edge.API.Token != exit.API.Token || edge.API.ReportToken != exit.API.ReportToken || edge.API.Token == edge.API.ReportToken {
		t.Fatal("generated API tokens do not match securely")
	}
	if edge.DNSProxy.Listen == "" || edge.Apply[0].Driver != "linux-edge" || exit.Apply[0].Driver != "nft-exit" {
		t.Fatalf("unexpected generated topology: edge=%+v exit=%+v", edge, exit)
	}
	for _, name := range []string{"edge.json", "exit.json"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode=%o", name, info.Mode().Perm())
		}
	}
}

func TestRuntimeStatusPersistsApplyAndLastError(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	runner := newFakeRunner()
	runtime, err := newRuntime(Config{Role: "controller", StateFile: state, API: APIConfig{Token: testReadToken, ReportToken: testReportToken}, Apply: []ApplyConfig{{Driver: "wg-route", Interface: "wg0", Peer: "peer"}}}, runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := LoadOperationalStatus(RuntimeStatusFile(state))
	if err != nil {
		t.Fatal(err)
	}
	if !status.AppliedKnown || status.Applied != 0 || status.LastApply.IsZero() {
		t.Fatalf("status=%+v", status)
	}
	runtime.mu.Lock()
	runtime.appliedKnown = false
	runtime.mu.Unlock()
	runner.failures[commandKey("wg", "set", "wg0", "peer", "peer", "allowed-ips", "")] = 1
	if err := runtime.reconcile(context.Background()); err == nil {
		t.Fatal("expected apply failure")
	}
	status, err = LoadOperationalStatus(RuntimeStatusFile(state))
	if err != nil || !strings.Contains(status.LastError, "injected failure") || status.LastErrorAt.IsZero() {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	b, _ := ioutil.ReadFile(RuntimeStatusFile(state))
	if strings.Contains(string(b), testReadToken) || strings.Contains(string(b), testReportToken) {
		t.Fatal("runtime status leaked an API token")
	}
}

func TestRuntimeStatusDoesNotRewriteUnchangedSnapshot(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	runtime, err := newRuntime(Config{Role: "controller", StateFile: state, API: APIConfig{Token: testReadToken, ReportToken: testReportToken}}, newFakeRunner())
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := RuntimeStatusFile(state)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := runtime.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("unchanged status was rewritten: %s -> %s", before.ModTime(), after.ModTime())
	}
}

func TestControllerStatusCountsReportedDesiredAsLearned(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	if err := SaveState(state, []string{"45.57.22.134/32"}); err != nil {
		t.Fatal(err)
	}
	runtime, err := newRuntime(Config{Role: "controller", StateFile: state, API: APIConfig{Token: testReadToken, ReportToken: testReportToken}}, newFakeRunner())
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := LoadOperationalStatus(RuntimeStatusFile(state))
	if err != nil || status.Learned != 1 || status.Applied != 1 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestCleanupDeletesOnlyOwnedNFTTable(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	runner := newFakeRunner()
	config := Config{StateFile: state, Apply: []ApplyConfig{{Driver: "nft-exit", Chain: "owned_table"}}}
	if err := Cleanup(config, runner); err != nil {
		t.Fatal(err)
	}
	commands := runner.commandLines()
	if !strings.Contains(commands, "nft delete table inet owned_table") || strings.Contains(commands, "flush ruleset") {
		t.Fatalf("unsafe cleanup:\n%s", commands)
	}
}

func TestCleanupLinuxEdgeAvoidsMainTableFlush(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	if err := SaveState(state, []string{"45.57.22.134/32"}); err != nil {
		t.Fatal(err)
	}
	runner := newFakeRunner()
	runner.outputs[commandKey("ip", "rule", "show")] = "12020: from all fwmark 0x20000000/0xff000000 lookup 202\n"
	runner.outputs[commandKey("ip", "route", "show", "table", "202")] = "default dev wg0\n"
	config := Config{StateFile: state, Apply: []ApplyConfig{{Driver: "linux-edge", Interface: "wg0", Peer: "peer", SourceNet: "192.168.8.0/24", BaseAllowed: []string{"10.8.0.0/24"}}}}
	if err := Cleanup(config, runner); err != nil {
		t.Fatal(err)
	}
	commands := runner.commandLines()
	if strings.Contains(commands, "flush table main") || !strings.Contains(commands, "ip route del default table 202") || !strings.Contains(commands, "allowed-ips 10.8.0.0/24") {
		t.Fatalf("unexpected cleanup:\n%s", commands)
	}
}

func TestSmokeTestResolvesAndConfirmsPolicyRoute(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("network namespace does not allow listeners: %v", err)
	}
	server := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("45.57.22.134")}}
		_ = w.WriteMsg(response)
	})}
	go server.ActivateAndServe()
	defer server.Shutdown()
	runner := newFakeRunner()
	runner.outputs[commandKey("ip", "route", "get", "45.57.22.134", "mark", "0x20000000")] = "45.57.22.134 dev wg-relay table 202\n"
	state := filepath.Join(t.TempDir(), "state")
	if err := saveOperationalStatus(RuntimeStatusFile(state), OperationalStatus{Version: 1, Role: "agent", AppliedKnown: true, Learned: 1, Applied: 1, Reported: 1}); err != nil {
		t.Fatal(err)
	}
	config := Config{Role: "agent", StateFile: state, DNSProxy: DNSProxyConfig{Listen: packet.LocalAddr().String()}, Apply: []ApplyConfig{{Driver: "linux-edge", Interface: "wg-relay"}}}
	result, err := SmokeTest(config, runner, "android.prod.cloud.netflix.com")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Confirmed || result.Progress != "1 -> 1 -> 1" || len(result.Addresses) != 1 || result.Addresses[0] != "45.57.22.134" {
		t.Fatalf("result=%+v", result)
	}
}
