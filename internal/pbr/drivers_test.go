package pbr

import (
	"strings"
	"testing"
)

func TestLinuxExitDropsNonNetflixAndLimitsNAT(t *testing.T) {
	runner := newFakeRunner()
	c := ApplyConfig{Driver: "linux-exit", SourceNet: "10.66.0.0/24", WANInterface: "eth0", Chain: "NETFLIX_EXIT"}
	if err := applyExit(runner, c, []string{"45.57.22.134/32"}); err != nil {
		t.Fatal(err)
	}
	input := runner.inputs()
	for _, required := range []string{
		"-A NETFLIX_EXIT -s 10.66.0.0/24 -d 45.57.22.134/32 -j ACCEPT",
		"-A NETFLIX_EXIT -s 10.66.0.0/24 -j DROP",
		"-A NETFLIX_EXIT_NAT -s 10.66.0.0/24 -d 45.57.22.134/32 -o eth0 -j MASQUERADE",
	} {
		if !strings.Contains(input, required) {
			t.Fatalf("missing %q in:\n%s", required, input)
		}
	}
	if strings.Contains(input, "-s 10.66.0.0/24 -o eth0 -j MASQUERADE") {
		t.Fatalf("found unrestricted masquerade in:\n%s", input)
	}
	if strings.Contains(input, "conntrack") {
		t.Fatalf("exit rules require optional conntrack extension:\n%s", input)
	}
}

func TestLinuxExitDoesNotInstallHooksWhenRestoreFails(t *testing.T) {
	runner := newFakeRunner()
	runner.failures[commandKey("/sbin/iptables-restore", "--noflush")] = 1
	c := ApplyConfig{Driver: "linux-exit", SourceNet: "10.66.0.0/24", WANInterface: "eth0", Chain: "NETFLIX_EXIT"}
	if err := applyExit(runner, c, []string{"45.57.22.134/32"}); err == nil {
		t.Fatal("expected restore failure")
	}
	commands := runner.commandLines()
	if strings.Contains(commands, "iptables -I FORWARD") || strings.Contains(commands, "iptables -t nat -I POSTROUTING") {
		t.Fatalf("hooks installed after failed restore:\n%s", commands)
	}
}

func TestLinuxEdgeUsesDedicatedTableOnly(t *testing.T) {
	runner := newFakeRunner()
	runner.outputs[commandKey("ip", "rule", "show")] = ""
	c := ApplyConfig{Driver: "linux-edge", Interface: "wg-relay", Peer: "peer", BaseAllowed: []string{"0.0.0.0/0"}, SourceNet: "192.168.8.0/24"}
	if err := applyEdge(runner, c, []string{"45.57.22.134/32"}); err != nil {
		t.Fatal(err)
	}
	input := runner.inputs()
	if !strings.Contains(input, "route replace default dev wg-relay table 202") {
		t.Fatalf("missing table default: %s", input)
	}
	if strings.Contains(input, "route replace 45.57.22.134/32") {
		t.Fatalf("destination route leaked outside policy table: %s", input)
	}
}

func TestLinuxEdgeUsesMaskedMarkConfiguredInputAndOnlinkNextHop(t *testing.T) {
	runner := newFakeRunner()
	runner.outputs[commandKey("ip", "rule", "show")] = ""
	c := ApplyConfig{Driver: "linux-edge", Interface: "wg-relay", InputInterface: "lan0", Peer: "peer", NextHop: "10.8.0.108", SourceNet: "192.168.8.0/24"}
	if err := applyEdge(runner, c, []string{"45.57.22.134/32"}); err != nil {
		t.Fatal(err)
	}
	if input := runner.inputs(); !strings.Contains(input, "route replace default via 10.8.0.108 dev wg-relay onlink table 202") || !strings.Contains(input, "MARK --set-xmark 0x20000000/0xff000000") {
		t.Fatalf("unexpected generated input:\n%s", input)
	}
	if commands := runner.commandLines(); !strings.Contains(commands, "-i lan0 -s 192.168.8.0/24") {
		t.Fatalf("configured input interface not used:\n%s", commands)
	}
}

func TestLinuxEdgeReturnsCriticalHookFailure(t *testing.T) {
	runner := newFakeRunner()
	runner.outputs[commandKey("ip", "rule", "show")] = ""
	runner.failures[commandKey("iptables", "-t", "mangle", "-C", "PREROUTING", "-i", "br+", "-s", "192.168.8.0/24", "-j", "STREAM_PBR")] = 1
	runner.failures[commandKey("iptables", "-t", "mangle", "-I", "PREROUTING", "1", "-i", "br+", "-s", "192.168.8.0/24", "-j", "STREAM_PBR")] = 1
	c := ApplyConfig{Driver: "linux-edge", Interface: "wg-relay", Peer: "peer", SourceNet: "192.168.8.0/24"}
	if err := applyEdge(runner, c, []string{"45.57.22.134/32"}); err == nil {
		t.Fatal("expected critical iptables hook failure")
	}
}

func TestLinuxEdgeDoesNotInstallHookWhenRestoreFails(t *testing.T) {
	runner := newFakeRunner()
	runner.outputs[commandKey("ip", "rule", "show")] = ""
	runner.failures[commandKey("/sbin/iptables-restore", "--noflush")] = 1
	c := ApplyConfig{Driver: "linux-edge", Interface: "wg-relay", Peer: "peer", SourceNet: "192.168.8.0/24"}
	if err := applyEdge(runner, c, []string{"45.57.22.134/32"}); err == nil {
		t.Fatal("expected restore failure")
	}
	if strings.Contains(runner.commandLines(), "iptables -t mangle -I PREROUTING") {
		t.Fatalf("hook installed after failed restore:\n%s", runner.commandLines())
	}
}

func TestEnsureIPRuleRejectsConflictingOwner(t *testing.T) {
	runner := newFakeRunner()
	runner.outputs[commandKey("ip", "rule", "show")] = "12020: from all lookup main\n"
	err := ensureIPRule(runner, "12020", "0x20000000", "0xff000000", "202")
	if err == nil || !strings.Contains(err.Error(), "owned by another rule") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(runner.commandLines(), "ip rule del") {
		t.Fatal("conflicting rule was deleted")
	}
}

func TestEnsureIPRuleRemovesOnlyExactDuplicates(t *testing.T) {
	runner := newFakeRunner()
	runner.outputs[commandKey("ip", "rule", "show")] = "12020: from all fwmark 0x20000000/0xff000000 lookup 202\n12020: from all fwmark 0x20000000/0xff000000 lookup 202\n"
	if err := ensureIPRule(runner, "12020", "0x20000000", "0xff000000", "202"); err != nil {
		t.Fatal(err)
	}
	commands := runner.commandLines()
	if strings.Count(commands, "ip rule del pref 12020 fwmark 0x20000000/0xff000000 lookup 202") != 2 {
		t.Fatalf("unexpected deletes:\n%s", commands)
	}
}

func TestWGRouteAndOpenWrtDriversGenerateCommands(t *testing.T) {
	wg := newFakeRunner()
	if err := applyWGRoute(wg, ApplyConfig{Interface: "wg0", Peer: "peer"}, []string{"45.57.22.134/32"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(wg.commandLines(), "wg set wg0 peer peer allowed-ips 45.57.22.134/32") {
		t.Fatal(wg.commandLines())
	}
	openwrt := newFakeRunner()
	c := ApplyConfig{PBRSection: "@policy[4]", FirewallSection: "@rule[13]"}
	if err := applyOpenWrt(openwrt, c, []string{"45.57.22.134/32"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(openwrt.commandLines(), "uci set pbr.@policy[4].dest_addr=45.57.22.134/32") {
		t.Fatal(openwrt.commandLines())
	}
}

func TestNFTExitCreatesFailClosedTableAndAtomicallyUpdatesSet(t *testing.T) {
	runner := newFakeRunner()
	runner.failures[commandKey("nft", "list", "table", "inet", "netflix_exit")] = 1
	c := ApplyConfig{Driver: "nft-exit", SourceNet: "192.168.8.0/24", WANInterface: "wan", Chain: "netflix_exit"}
	if err := applyNFTExit(runner, c, []string{"45.57.22.134/32"}); err != nil {
		t.Fatal(err)
	}
	input := runner.inputs()
	for _, required := range []string{
		"ip saddr 192.168.8.0/24 ip daddr @destinations accept",
		"ip saddr 192.168.8.0/24 drop",
		"oifname \"wan\" masquerade",
		"add element inet netflix_exit destinations { 45.57.22.134/32 }",
	} {
		if !strings.Contains(input, required) {
			t.Fatalf("missing %q in:\n%s", required, input)
		}
	}
}

func TestNFTExitRebuildsRulesWhenConfigurationChanges(t *testing.T) {
	runner := newFakeRunner()
	c := ApplyConfig{Driver: "nft-exit", SourceNet: "10.66.0.0/24", WANInterface: "eth0", Chain: "netflix_exit"}
	if err := applyNFTExit(runner, c, nil); err != nil {
		t.Fatal(err)
	}
	input := runner.inputs()
	if !strings.Contains(input, "delete table inet netflix_exit") || !strings.Contains(input, "ip saddr 10.66.0.0/24 drop") || !strings.Contains(input, "oifname \"eth0\"") {
		t.Fatalf("table was not fully rebuilt:\n%s", input)
	}
}
