package pbr

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

func applyNetworks(runner CommandRunner, c ApplyConfig, nets []string) error {
	switch c.Driver {
	case "wg-route":
		return applyWGRoute(runner, c, nets)
	case "linux-edge":
		return applyEdge(runner, c, nets)
	case "openwrt-pbr":
		return applyOpenWrt(runner, c, nets)
	case "linux-exit":
		return applyExit(runner, c, nets)
	case "nft-exit":
		return applyNFTExit(runner, c, nets)
	default:
		return fmt.Errorf("unknown driver %q", c.Driver)
	}
}

func reapplyNetworks(runner CommandRunner, c ApplyConfig, nets []string) error {
	if c.Driver == "openwrt-pbr" {
		return reconcileOpenWrt(runner, c, nets)
	}
	return applyNetworks(runner, c, nets)
}

func applyNFTExit(runner CommandRunner, c ApplyConfig, nets []string) error {
	if c.Chain == "" {
		c.Chain = "netflix_exit"
	}
	setName := "destinations"
	exists := succeeds(runner, "nft", "list", "table", "inet", c.Chain)
	var transaction strings.Builder
	if exists {
		transaction.WriteString("delete table inet " + c.Chain + "\n")
	}
	transaction.WriteString("add table inet " + c.Chain + "\n")
	transaction.WriteString("add set inet " + c.Chain + " " + setName + " { type ipv4_addr; flags interval; }\n")
	if len(nets) > 0 {
		transaction.WriteString("add element inet " + c.Chain + " " + setName + " { " + strings.Join(nets, ", ") + " }\n")
	}
	transaction.WriteString("add chain inet " + c.Chain + " forward { type filter hook forward priority -10; policy accept; }\n")
	transaction.WriteString("add rule inet " + c.Chain + " forward ip saddr " + c.SourceNet + " ip daddr @" + setName + " accept\n")
	transaction.WriteString("add rule inet " + c.Chain + " forward ip saddr " + c.SourceNet + " drop\n")
	transaction.WriteString("add chain inet " + c.Chain + " postrouting { type nat hook postrouting priority 100; policy accept; }\n")
	transaction.WriteString("add rule inet " + c.Chain + " postrouting ip saddr " + c.SourceNet + " ip daddr @" + setName + " oifname \"" + c.WANInterface + "\" masquerade\n")
	return runner.RunInput(transaction.String(), "nft", "-f", "-")
}

func succeeds(runner CommandRunner, name string, args ...string) bool {
	return runner.Run(name, args...) == nil
}

func routeBatch(runner CommandRunner, lines []string) error {
	if len(lines) == 0 {
		return nil
	}
	return runner.RunInput(strings.Join(lines, "\n")+"\n", "ip", "-force", "-batch", "-")
}

func restoreIPTables(runner CommandRunner, input string) error {
	if path, err := runner.LookPath("iptables-restore"); err == nil {
		return runner.RunInput(input, path, "--noflush")
	}
	if runner.Exists("/system/bin/xtables-multi") {
		return runner.RunInput(input, "/system/bin/xtables-multi", "iptables-restore", "--noflush")
	}
	return fmt.Errorf("iptables-restore not found")
}

func ensureChain(runner CommandRunner, table, chain string) error {
	args := []string{}
	if table != "filter" {
		args = append(args, "-t", table)
	}
	if succeeds(runner, "iptables", append(args, "-S", chain)...) {
		return nil
	}
	return runner.Run("iptables", append(args, "-N", chain)...)
}

func allowed(c ApplyConfig, nets []string) string {
	for _, base := range c.BaseAllowed {
		if base == "0.0.0.0/0" {
			return strings.Join(c.BaseAllowed, ",")
		}
	}
	return strings.Join(append(append([]string{}, c.BaseAllowed...), nets...), ",")
}

func ensureIPRule(runner CommandRunner, priority, mark, mask, table string) error {
	exact, err := inspectIPRule(runner, priority, mark, mask, table)
	if err != nil {
		return err
	}
	return ensureIPRuleCount(runner, exact, priority, mark, mask, table)
}

func ensureIPRuleJSON(runner CommandRunner, out []byte, priority, mark, mask, table string) error {
	exact, err := scanIPRuleJSON(out, priority, mark, mask, table)
	if err != nil {
		return err
	}
	return ensureIPRuleCount(runner, exact, priority, mark, mask, table)
}

func inspectIPRule(runner CommandRunner, priority, mark, mask, table string) (int, error) {
	out, err := runner.Output("ip", "-j", "rule", "show")
	if err == nil {
		exact, jsonErr := scanIPRuleJSON(out, priority, mark, mask, table)
		if jsonErr == nil || !strings.HasPrefix(jsonErr.Error(), "parse ip -j rule show:") {
			return exact, jsonErr
		}
	}
	return scanIPRuleText(runner, priority, mark, mask, table)
}

func scanIPRuleJSON(out []byte, priority, mark, mask, table string) (int, error) {
	var rules []map[string]json.RawMessage
	if err := json.Unmarshal(out, &rules); err != nil {
		return 0, fmt.Errorf("parse ip -j rule show: %v", err)
	}
	wantPriority, _ := strconv.Atoi(priority)
	wantMark, _ := strconv.ParseUint(mark, 0, 32)
	wantMask, _ := strconv.ParseUint(mask, 0, 32)
	exact := 0
	for _, rule := range rules {
		if rawInt(rule["priority"]) != wantPriority {
			continue
		}
		if !onlyExpectedIPRuleFields(rule) || !neutralRuleSelector(rule["src"]) || !neutralRuleSelector(rule["dst"]) || !neutralRuleProtocol(rule["protocol"]) {
			return 0, fmt.Errorf("ip rule priority %s is already owned by another rule", priority)
		}
		ruleMark, markErr := strconv.ParseUint(rawString(rule["fwmark"]), 0, 32)
		ruleMask := uint64(0xffffffff)
		var maskErr error
		if value := rawString(rule["fwmask"]); value != "" {
			ruleMask, maskErr = strconv.ParseUint(value, 0, 32)
		}
		if markErr == nil && maskErr == nil && ruleMark == wantMark && ruleMask == wantMask && rawString(rule["table"]) == table {
			exact++
			continue
		}
		return 0, fmt.Errorf("ip rule priority %s is already owned by another rule", priority)
	}
	return exact, nil
}

func onlyExpectedIPRuleFields(rule map[string]json.RawMessage) bool {
	for field := range rule {
		switch field {
		case "priority", "src", "dst", "fwmark", "fwmask", "table", "protocol":
		default:
			return false
		}
	}
	return true
}

func neutralRuleSelector(value json.RawMessage) bool {
	selector := rawString(value)
	return selector == "" || selector == "all"
}

func neutralRuleProtocol(value json.RawMessage) bool {
	protocol := rawString(value)
	return protocol == "" || protocol == "boot"
}

func rawString(value json.RawMessage) string {
	if len(value) == 0 {
		return ""
	}
	var result string
	if err := json.Unmarshal(value, &result); err == nil {
		return result
	}
	return strings.TrimSpace(string(value))
}

func rawInt(value json.RawMessage) int {
	result, _ := strconv.Atoi(rawString(value))
	return result
}

func ensureIPRuleText(runner CommandRunner, priority, mark, mask, table string) error {
	exact, err := scanIPRuleText(runner, priority, mark, mask, table)
	if err != nil {
		return err
	}
	return ensureIPRuleCount(runner, exact, priority, mark, mask, table)
}

func scanIPRuleText(runner CommandRunner, priority, mark, mask, table string) (int, error) {
	out, err := runner.Output("ip", "rule", "show")
	if err != nil {
		return 0, err
	}
	expected := []string{"from", "all", "fwmark", mark + "/" + mask, "lookup", table}
	exact := 0
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.TrimSuffix(fields[0], ":") != priority {
			continue
		}
		if Equal(fields[1:], expected) {
			exact++
			continue
		}
		return 0, fmt.Errorf("ip rule priority %s is already owned by another rule: %s", priority, strings.TrimSpace(line))
	}
	return exact, nil
}

func ensureIPRuleCount(runner CommandRunner, exact int, priority, mark, mask, table string) error {
	if exact == 1 {
		return nil
	}
	deleteArgs := []string{"rule", "del", "pref", priority, "fwmark", mark + "/" + mask, "lookup", table}
	for i := 0; i < exact; i++ {
		if err := runner.Run("ip", deleteArgs...); err != nil {
			return err
		}
	}
	return runner.Run("ip", "rule", "add", "pref", priority, "fwmark", mark+"/"+mask, "lookup", table)
}

func deleteOwnedIPRule(runner CommandRunner, priority, mark, mask, table string) error {
	exact, err := inspectIPRule(runner, priority, mark, mask, table)
	if err != nil {
		return err
	}
	args := []string{"rule", "del", "pref", priority, "fwmark", mark + "/" + mask, "lookup", table}
	for i := 0; i < exact; i++ {
		if err := runner.Run("ip", args...); err != nil {
			return err
		}
	}
	return nil
}

func applyWGRoute(runner CommandRunner, c ApplyConfig, nets []string) error {
	if err := runner.Run("wg", "set", c.Interface, "peer", c.Peer, "allowed-ips", allowed(c, nets)); err != nil {
		return err
	}
	lines := make([]string, 0, len(nets))
	for _, network := range nets {
		lines = append(lines, "route replace "+network+" dev "+c.Interface)
	}
	return routeBatch(runner, lines)
}

func applyEdge(runner CommandRunner, c ApplyConfig, nets []string) error {
	withEdgeDefaults(&c)
	if err := runner.Run("wg", "set", c.Interface, "peer", c.Peer, "allowed-ips", allowed(c, nets)); err != nil {
		return err
	}
	routeTarget := "dev " + c.Interface
	if c.NextHop != "" {
		routeTarget = "via " + c.NextHop + " " + routeTarget + " onlink"
	}
	if err := routeBatch(runner, []string{"route replace default " + routeTarget + " table " + c.Table}); err != nil {
		return err
	}
	if err := ensureIPRule(runner, c.RulePriority, c.Mark, c.Mask, c.Table); err != nil {
		return err
	}
	if err := ensureChain(runner, "mangle", c.Chain); err != nil {
		return err
	}
	var restore strings.Builder
	restore.WriteString("*mangle\n-F " + c.Chain + "\n")
	for _, network := range nets {
		restore.WriteString("-A " + c.Chain + " -d " + network + " -j MARK --set-xmark " + c.Mark + "/" + c.Mask + "\n")
	}
	restore.WriteString("COMMIT\n")
	if err := restoreIPTables(runner, restore.String()); err != nil {
		return err
	}
	hook := []string{"-t", "mangle", "-C", "PREROUTING", "-i", c.InputInterface, "-s", c.SourceNet, "-j", c.Chain}
	if succeeds(runner, "iptables", hook...) {
		return nil
	}
	insert := append([]string{"-t", "mangle", "-I", "PREROUTING", "1"}, hook[4:]...)
	return runner.Run("iptables", insert...)
}

func withEdgeDefaults(c *ApplyConfig) {
	if c.Chain == "" {
		c.Chain = "STREAM_PBR"
	}
	if c.Table == "" {
		c.Table = "202"
	}
	if c.Mark == "" {
		c.Mark = "0x20000000"
	}
	if c.Mask == "" {
		c.Mask = "0xff000000"
	}
	if c.RulePriority == "" {
		c.RulePriority = "12020"
	}
	if c.InputInterface == "" {
		c.InputInterface = "br+"
	}
}

func applyOpenWrt(runner CommandRunner, c ApplyConfig, nets []string) error {
	if err := runner.Run("uci", "set", "pbr."+c.PBRSection+".dest_addr="+strings.Join(nets, " ")); err != nil {
		return err
	}
	_ = runner.Run("uci", "-q", "delete", "firewall."+c.FirewallSection+".dest_ip")
	for _, network := range nets {
		if err := runner.Run("uci", "add_list", "firewall."+c.FirewallSection+".dest_ip="+network); err != nil {
			return err
		}
	}
	for _, args := range [][]string{{"commit", "pbr"}, {"commit", "firewall"}} {
		if err := runner.Run("uci", args...); err != nil {
			return err
		}
	}
	if err := runner.Run("/etc/init.d/firewall", "reload"); err != nil {
		return err
	}
	return runner.Run("/etc/init.d/pbr", "reload")
}

func reconcileOpenWrt(runner CommandRunner, c ApplyConfig, nets []string) error {
	pbrNetworks, pbrOK := readUCIList(runner, "pbr."+c.PBRSection+".dest_addr", len(nets) == 0)
	firewallNetworks, firewallOK := readUCIList(runner, "firewall."+c.FirewallSection+".dest_ip", len(nets) == 0)
	if !pbrOK || !firewallOK || !Equal(pbrNetworks, nets) || !Equal(firewallNetworks, nets) {
		return applyOpenWrt(runner, c, nets)
	}
	if !succeeds(runner, "/etc/init.d/firewall", "status") {
		if err := runner.Run("/etc/init.d/firewall", "reload"); err != nil {
			return err
		}
	}
	if !succeeds(runner, "/etc/init.d/pbr", "status") {
		return runner.Run("/etc/init.d/pbr", "reload")
	}
	return nil
}

func readUCIList(runner CommandRunner, option string, absentOK bool) ([]string, bool) {
	out, err := runner.Output("uci", "-q", "get", option)
	if err != nil {
		return nil, absentOK
	}
	fields := strings.Fields(string(out))
	limit := len(fields)
	if limit == 0 {
		limit = 1
	}
	values, err := ValidateNetworks(fields, false, limit)
	return values, err == nil
}

func applyExit(runner CommandRunner, c ApplyConfig, nets []string) error {
	if c.Chain == "" {
		c.Chain = "STREAM_EXIT"
	}
	natChain := c.Chain + "_NAT"
	if err := ensureChain(runner, "filter", c.Chain); err != nil {
		return err
	}
	if err := ensureChain(runner, "nat", natChain); err != nil {
		return err
	}
	legacy := []string{"-t", "nat", "-C", "POSTROUTING", "-s", c.SourceNet, "-o", c.WANInterface, "-j", "MASQUERADE"}
	if succeeds(runner, "iptables", legacy...) {
		if err := runner.Run("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", c.SourceNet, "-o", c.WANInterface, "-j", "MASQUERADE"); err != nil {
			return err
		}
	}
	var restore strings.Builder
	restore.WriteString("*filter\n-F " + c.Chain + "\n")
	for _, network := range nets {
		restore.WriteString("-A " + c.Chain + " -s " + c.SourceNet + " -d " + network + " -j ACCEPT\n")
	}
	restore.WriteString("-A " + c.Chain + " -s " + c.SourceNet + " -j DROP\n")
	restore.WriteString("-A " + c.Chain + " -j RETURN\nCOMMIT\n")
	restore.WriteString("*nat\n-F " + natChain + "\n")
	for _, network := range nets {
		restore.WriteString("-A " + natChain + " -s " + c.SourceNet + " -d " + network + " -o " + c.WANInterface + " -j MASQUERADE\n")
	}
	restore.WriteString("-A " + natChain + " -j RETURN\nCOMMIT\n")
	if err := restoreIPTables(runner, restore.String()); err != nil {
		return err
	}
	filterHook := []string{"-C", "FORWARD", "-j", c.Chain}
	if !succeeds(runner, "iptables", filterHook...) {
		if err := runner.Run("iptables", "-I", "FORWARD", "1", "-j", c.Chain); err != nil {
			return err
		}
	}
	natHook := []string{"-t", "nat", "-C", "POSTROUTING", "-j", natChain}
	if !succeeds(runner, "iptables", natHook...) {
		if err := runner.Run("iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-j", natChain); err != nil {
			return err
		}
	}
	return nil
}
