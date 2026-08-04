package pbr

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

type CheckResult struct {
	Name   string
	OK     bool
	Detail string
}

func Doctor(ctx context.Context, config Config, runner CommandRunner) []CheckResult {
	checks := []CheckResult{{Name: "config", OK: true, Detail: "valid"}}
	for _, apply := range config.Apply {
		if apply.Interface != "" {
			checks = append(checks, commandCheck(runner, "interface "+apply.Interface, "ip", "link", "show", "dev", apply.Interface))
		}
		if apply.Peer != "" && apply.Interface != "" {
			out, err := runner.Output("wg", "show", apply.Interface, "peers")
			checks = append(checks, CheckResult{Name: "WireGuard peer", OK: err == nil && containsLine(string(out), apply.Peer), Detail: detail(err, apply.Peer)})
		}
		switch apply.Driver {
		case "nft-exit":
			chain := apply.Chain
			if chain == "" {
				chain = "netflix_exit"
			}
			checks = append(checks, commandCheck(runner, "nft table", "nft", "list", "table", "inet", chain))
		case "linux-edge":
			withEdgeDefaults(&apply)
			checks = append(checks, commandCheck(runner, "ip rule", "ip", "rule", "show"))
			checks = append(checks, commandCheck(runner, "iptables chain", "iptables", "-t", "mangle", "-S", apply.Chain))
		case "linux-exit":
			checks = append(checks, commandCheck(runner, "iptables", "iptables", "-S"))
		}
		state, stateErr := LoadState(config.StateFile)
		if stateErr == nil && len(state) > 0 && (apply.Driver == "linux-edge" || apply.Driver == "wg-route") {
			address := strings.SplitN(state[0], "/", 2)[0]
			args := []string{"route", "get", address}
			if apply.Driver == "linux-edge" {
				withEdgeDefaults(&apply)
				args = append(args, "mark", apply.Mark)
			}
			route, routeOK, routeErr := policyRoute(runner, args, apply)
			checks = append(checks, CheckResult{Name: "learned route", OK: routeOK, Detail: detail(routeErr, route)})
		}
	}
	if config.Role == "agent" {
		checks = append(checks, apiCheck(ctx, config.API.SourceURL, config.API.Token))
	} else if config.API.Listen != "" {
		scheme := "http"
		if config.API.TLSCert != "" {
			scheme = "https"
		}
		checks = append(checks, apiCheck(ctx, scheme+"://"+ResolveHostPort(config.API.Listen)+"/v1/networks", config.API.Token))
	}
	if config.DNSProxy.Listen != "" {
		checks = append(checks, dnsCheck(config.DNSProxy.Listen, "example.com.", "udp"))
		checks = append(checks, dnsCheck(config.DNSProxy.Listen, "example.com.", "tcp"))
	}
	status, err := LoadOperationalStatus(RuntimeStatusFile(config.StateFile))
	if err != nil {
		checks = append(checks, CheckResult{Name: "runtime status", OK: false, Detail: err.Error()})
	} else {
		checks = append(checks, CheckResult{Name: "learned -> applied", OK: status.AppliedKnown && status.Applied >= status.Learned, Detail: fmt.Sprintf("%d -> %d", status.Learned, status.Applied)})
		if config.Role == "agent" {
			checks = append(checks, CheckResult{Name: "learned -> reported", OK: status.Reported >= status.Learned, Detail: fmt.Sprintf("%d -> %d", status.Learned, status.Reported)})
		}
	}
	return checks
}

func apiCheck(ctx context.Context, url, token string) CheckResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err == nil {
		req.Header.Set("Authorization", "Bearer "+token)
		client := &http.Client{Timeout: 5 * time.Second}
		var response *http.Response
		response, err = client.Do(req)
		if err == nil {
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				err = fmt.Errorf("HTTP %s", response.Status)
			}
		}
	}
	return CheckResult{Name: "controller API", OK: err == nil, Detail: detail(err, url)}
}

func dnsCheck(address, name, network string) CheckResult {
	request := new(dns.Msg)
	request.SetQuestion(name, dns.TypeA)
	response, _, err := (&dns.Client{Net: network, Timeout: 5 * time.Second}).Exchange(request, address)
	if err == nil && response.Rcode != dns.RcodeSuccess {
		err = fmt.Errorf("rcode %s", dns.RcodeToString[response.Rcode])
	}
	return CheckResult{Name: "DNS proxy " + strings.ToUpper(network), OK: err == nil, Detail: detail(err, address)}
}

func commandCheck(runner CommandRunner, label, command string, args ...string) CheckResult {
	err := runner.Run(command, args...)
	return CheckResult{Name: label, OK: err == nil, Detail: detail(err, command)}
}

func detail(err error, success string) string {
	if err != nil {
		return err.Error()
	}
	return success
}

func containsLine(output, expected string) bool {
	for _, line := range strings.Fields(output) {
		if line == expected {
			return true
		}
	}
	return false
}

type SmokeResult struct {
	Name       string
	Addresses  []string
	Route      string
	Progress   string
	Confirmed  bool
	StatusFile string
}

func SmokeTest(config Config, runner CommandRunner, name string) (SmokeResult, error) {
	result := SmokeResult{Name: name, StatusFile: RuntimeStatusFile(config.StateFile)}
	if config.DNSProxy.Listen == "" {
		return result, fmt.Errorf("smoke-test requires dns_proxy on this host")
	}
	if name == "" {
		name = "android.prod.cloud.netflix.com."
		result.Name = name
	}
	request := new(dns.Msg)
	request.SetQuestion(dns.Fqdn(name), dns.TypeA)
	response, _, err := (&dns.Client{Net: "udp", Timeout: 10 * time.Second}).Exchange(request, config.DNSProxy.Listen)
	if err != nil {
		return result, err
	}
	if response.Rcode != dns.RcodeSuccess {
		return result, fmt.Errorf("DNS returned %s", dns.RcodeToString[response.Rcode])
	}
	for _, answer := range response.Answer {
		if record, ok := answer.(*dns.A); ok {
			result.Addresses = append(result.Addresses, record.A.String())
		}
	}
	if len(result.Addresses) == 0 {
		return result, fmt.Errorf("DNS response contained no IPv4 addresses")
	}
	address := result.Addresses[0]
	for _, apply := range config.Apply {
		switch apply.Driver {
		case "linux-edge":
			withEdgeDefaults(&apply)
			result.Route, result.Confirmed, err = policyRoute(runner, []string{"route", "get", address, "mark", apply.Mark}, apply)
			if err != nil {
				return result, err
			}
		case "wg-route":
			out, routeErr := runner.Output("ip", "route", "get", address)
			if routeErr != nil {
				return result, routeErr
			}
			result.Route = strings.TrimSpace(string(out))
			result.Confirmed = strings.Contains(result.Route, "dev "+apply.Interface)
		}
	}
	if !result.Confirmed {
		return result, fmt.Errorf("learned address is not routed through the configured interface: %s", result.Route)
	}
	status, err := LoadOperationalStatus(result.StatusFile)
	if err != nil {
		return result, fmt.Errorf("runtime status: %v", err)
	}
	result.Progress = fmt.Sprintf("%d -> %d -> %d", status.Learned, status.Applied, status.Reported)
	if !status.AppliedKnown || config.Role == "agent" && status.Reported < status.Learned {
		return result, fmt.Errorf("runtime progress is incomplete: %s", result.Progress)
	}
	return result, nil
}

func policyRoute(runner CommandRunner, routeArgs []string, apply ApplyConfig) (string, bool, error) {
	out, err := runner.Output("ip", routeArgs...)
	if err == nil {
		route := strings.TrimSpace(string(out))
		return route, strings.Contains(route, "dev "+apply.Interface), nil
	}
	if apply.Table == "" {
		return "", false, err
	}
	// Android's toybox ip omits the mark selector. Its dedicated policy table
	// still provides a deterministic, inspectable proof of the selected path.
	out, tableErr := runner.Output("ip", "route", "show", "table", apply.Table)
	if tableErr != nil {
		return "", false, err
	}
	route := "table " + apply.Table + ": " + strings.TrimSpace(string(out))
	return route, strings.Contains(string(out), "dev "+apply.Interface), nil
}

func Cleanup(config Config, runner CommandRunner) error {
	state, err := LoadState(config.StateFile)
	if err != nil {
		return err
	}
	for i := len(config.Apply) - 1; i >= 0; i-- {
		apply := config.Apply[i]
		switch apply.Driver {
		case "nft-exit":
			if apply.Chain == "" {
				apply.Chain = "netflix_exit"
			}
			if succeeds(runner, "nft", "list", "table", "inet", apply.Chain) {
				if err := runner.Run("nft", "delete", "table", "inet", apply.Chain); err != nil {
					return err
				}
			}
		case "wg-route":
			if err := runner.Run("wg", "set", apply.Interface, "peer", apply.Peer, "allowed-ips", strings.Join(apply.BaseAllowed, ",")); err != nil {
				return err
			}
			for _, network := range state {
				_ = runner.Run("ip", "route", "del", network, "dev", apply.Interface)
			}
		case "linux-edge":
			withEdgeDefaults(&apply)
			hook := []string{"-t", "mangle", "-C", "PREROUTING", "-i", apply.InputInterface, "-s", apply.SourceNet, "-j", apply.Chain}
			if succeeds(runner, "iptables", hook...) {
				if err := runner.Run("iptables", "-t", "mangle", "-D", "PREROUTING", "-i", apply.InputInterface, "-s", apply.SourceNet, "-j", apply.Chain); err != nil {
					return err
				}
			}
			if succeeds(runner, "iptables", "-t", "mangle", "-S", apply.Chain) {
				if err := runner.Run("iptables", "-t", "mangle", "-F", apply.Chain); err != nil {
					return err
				}
				if err := runner.Run("iptables", "-t", "mangle", "-X", apply.Chain); err != nil {
					return err
				}
			}
			if out, err := runner.Output("ip", "rule", "show"); err == nil && strings.Contains(string(out), apply.RulePriority+":") && strings.Contains(string(out), "fwmark "+apply.Mark+"/"+apply.Mask) && strings.Contains(string(out), "lookup "+apply.Table) {
				if err := runner.Run("ip", "rule", "del", "pref", apply.RulePriority, "fwmark", apply.Mark+"/"+apply.Mask, "lookup", apply.Table); err != nil {
					return err
				}
			}
			if out, err := runner.Output("ip", "route", "show", "table", apply.Table); err == nil && strings.Contains(string(out), "default") {
				if err := runner.Run("ip", "route", "del", "default", "table", apply.Table); err != nil {
					return err
				}
			}
			if err := runner.Run("wg", "set", apply.Interface, "peer", apply.Peer, "allowed-ips", strings.Join(apply.BaseAllowed, ",")); err != nil {
				return err
			}
		case "linux-exit":
			cleanupLinuxExit(runner, apply)
		case "openwrt-pbr":
			_ = runner.Run("uci", "-q", "delete", "pbr."+apply.PBRSection+".dest_addr")
			_ = runner.Run("uci", "-q", "delete", "firewall."+apply.FirewallSection+".dest_ip")
			if err := runner.Run("uci", "commit", "pbr"); err != nil {
				return err
			}
			if err := runner.Run("uci", "commit", "firewall"); err != nil {
				return err
			}
			_ = runner.Run("/etc/init.d/firewall", "reload")
			_ = runner.Run("/etc/init.d/pbr", "reload")
		}
	}
	return nil
}

func cleanupLinuxExit(runner CommandRunner, apply ApplyConfig) {
	if apply.Chain == "" {
		apply.Chain = "STREAM_EXIT"
	}
	natChain := apply.Chain + "_NAT"
	_ = runner.Run("iptables", "-D", "FORWARD", "-j", apply.Chain)
	_ = runner.Run("iptables", "-t", "nat", "-D", "POSTROUTING", "-j", natChain)
	_ = runner.Run("iptables", "-F", apply.Chain)
	_ = runner.Run("iptables", "-X", apply.Chain)
	_ = runner.Run("iptables", "-t", "nat", "-F", natChain)
	_ = runner.Run("iptables", "-t", "nat", "-X", natChain)
}

func Uninstall(configPath string, purge bool, runner CommandRunner) (InstallLayout, error) {
	layout := DetectInstallLayout()
	if os.Geteuid() != 0 {
		return layout, fmt.Errorf("uninstall must run as root")
	}
	config, err := LoadConfig(configPath)
	if err != nil {
		return layout, err
	}
	if err := stopService(layout, config, runner); err != nil {
		return layout, err
	}
	if err := Cleanup(config, runner); err != nil {
		return layout, err
	}
	_ = os.Remove(layout.Service)
	_ = os.Remove(layout.Binary)
	if layout.Platform == "systemd" {
		_ = runner.Run("systemctl", "daemon-reload")
	}
	if purge {
		_ = os.Remove(layout.Config)
		_ = os.Remove(config.StateFile)
		_ = os.Remove(learnedStateFile(config.StateFile))
		_ = os.Remove(RuntimeStatusFile(config.StateFile))
	}
	return layout, nil
}

func stopService(layout InstallLayout, config Config, runner CommandRunner) error {
	switch layout.Platform {
	case "systemd":
		if err := runner.Run("systemctl", "disable", "--now", "netflix-pbrd"); err != nil {
			return err
		}
		return runner.Run("systemctl", "daemon-reload")
	case "openwrt":
		_ = runner.Run(layout.Service, "disable")
		return runner.Run(layout.Service, "stop")
	default:
		status, err := LoadOperationalStatus(RuntimeStatusFile(config.StateFile))
		if err != nil || status.PID <= 1 || status.PID == os.Getpid() {
			return fmt.Errorf("cannot identify Entware daemon PID safely; run %s stop first", layout.Service)
		}
		if err := syscall.Kill(status.PID, syscall.SIGTERM); err != nil && err != syscall.ESRCH {
			return err
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if err := syscall.Kill(status.PID, 0); err == syscall.ESRCH {
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
		return fmt.Errorf("Entware daemon PID %d did not stop", status.PID)
	}
}

func ResolveHostPort(address string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	if host == "0.0.0.0" || host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}
