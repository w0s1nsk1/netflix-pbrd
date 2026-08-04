package pbr

import (
	"fmt"
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
	out, err := runner.Output("ip", "rule", "show")
	if err != nil {
		return err
	}
	prefix := priority + ":"
	exact := 0
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		if strings.Contains(line, "fwmark "+mark+"/"+mask) && strings.Contains(line, "lookup "+table) {
			exact++
			continue
		}
		return fmt.Errorf("ip rule priority %s is already owned by another rule: %s", priority, line)
	}
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
