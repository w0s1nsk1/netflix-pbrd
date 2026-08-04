package pbr

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

var (
	interfacePattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9_@.\[\]-]+$`)
	chainPattern      = regexp.MustCompile(`^[A-Za-z0-9_]{1,20}$`)
	hexPattern        = regexp.MustCompile(`^0x[0-9A-Fa-f]{1,8}$`)
)

type Config struct {
	Role         string         `json:"role"`
	Interval     string         `json:"interval"`
	StateFile    string         `json:"state_file"`
	SeedNetworks []string       `json:"seed_networks"`
	API          APIConfig      `json:"api"`
	DNSProxy     DNSProxyConfig `json:"dns_proxy"`
	Apply        []ApplyConfig  `json:"apply"`
	MaxNetworks  int            `json:"max_networks"`
}

type APIConfig struct {
	Listen            string `json:"listen"`
	SourceURL         string `json:"source_url"`
	Token             string `json:"token"`
	ReportToken       string `json:"report_token"`
	TLSCert           string `json:"tls_cert"`
	TLSKey            string `json:"tls_key"`
	AllowInsecureHTTP bool   `json:"allow_insecure_http"`
}

type DNSProxyConfig struct {
	Listen          string   `json:"listen"`
	Upstream        string   `json:"upstream"`
	TrustedSuffixes []string `json:"trusted_suffixes"`
	ServicePrefixes []string `json:"service_prefixes"`
}

type ApplyConfig struct {
	Driver          string   `json:"driver"`
	Interface       string   `json:"interface"`
	Peer            string   `json:"peer"`
	BaseAllowed     []string `json:"base_allowed"`
	NextHop         string   `json:"next_hop"`
	SourceNet       string   `json:"source_net"`
	WANInterface    string   `json:"wan_interface"`
	Table           string   `json:"table"`
	RulePriority    string   `json:"rule_priority"`
	Mark            string   `json:"mark"`
	Mask            string   `json:"mask"`
	Chain           string   `json:"chain"`
	PBRSection      string   `json:"pbr_section"`
	FirewallSection string   `json:"firewall_section"`
}

func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.Role != "controller" && c.Role != "agent" {
		return c, fmt.Errorf("role must be controller or agent")
	}
	if c.StateFile == "" {
		return c, fmt.Errorf("state_file is required")
	}
	if c.Role == "agent" && c.API.SourceURL == "" {
		return c, fmt.Errorf("agent requires api.source_url")
	}
	if c.Role == "agent" {
		u, err := url.Parse(c.API.SourceURL)
		if err != nil || u.Host == "" || u.Scheme == "" {
			return c, fmt.Errorf("api.source_url must be an absolute URL")
		}
		if u.Scheme != "https" && !c.API.AllowInsecureHTTP {
			return c, fmt.Errorf("HTTPS source_url is required unless allow_insecure_http is true")
		}
	}
	if c.API.Token == "" {
		return c, fmt.Errorf("api.token is required")
	}
	if len(c.API.Token) < 32 {
		return c, fmt.Errorf("api.token must contain at least 32 characters")
	}
	if len(c.API.ReportToken) < 32 {
		return c, fmt.Errorf("api.report_token must contain at least 32 characters")
	}
	if c.API.ReportToken == c.API.Token {
		return c, fmt.Errorf("api.report_token must differ from api.token")
	}
	if c.MaxNetworks == 0 {
		c.MaxNetworks = DefaultMaxNetworks
	}
	if c.MaxNetworks < 1 || c.MaxNetworks > 65535 {
		return c, fmt.Errorf("max_networks must be between 1 and 65535")
	}
	if _, err := ValidateNetworks(c.SeedNetworks, false, c.MaxNetworks); err != nil {
		return c, fmt.Errorf("seed_networks: %v", err)
	}
	if c.Role == "controller" && c.API.Listen == "" {
		return c, fmt.Errorf("controller requires api.listen")
	}
	if c.API.Listen != "" && (c.API.TLSCert == "" || c.API.TLSKey == "") && !c.API.AllowInsecureHTTP {
		return c, fmt.Errorf("TLS is required unless allow_insecure_http is true")
	}
	if c.DNSProxy.Listen != "" || c.DNSProxy.Upstream != "" {
		if !validHostPort(c.DNSProxy.Listen) || !validHostPort(c.DNSProxy.Upstream) {
			return c, fmt.Errorf("dns_proxy.listen and dns_proxy.upstream must be valid host:port addresses")
		}
		if c.DNSProxy.Listen == c.DNSProxy.Upstream {
			return c, fmt.Errorf("dns_proxy.listen and dns_proxy.upstream must differ")
		}
	}
	for _, apply := range c.Apply {
		if apply.Interface != "" && !interfacePattern.MatchString(apply.Interface) {
			return c, fmt.Errorf("invalid interface %q", apply.Interface)
		}
		if apply.WANInterface != "" && !interfacePattern.MatchString(apply.WANInterface) {
			return c, fmt.Errorf("invalid wan_interface %q", apply.WANInterface)
		}
		if apply.Chain != "" && !chainPattern.MatchString(apply.Chain) {
			return c, fmt.Errorf("invalid chain %q", apply.Chain)
		}
		if apply.Table != "" && !identifierPattern.MatchString(apply.Table) {
			return c, fmt.Errorf("invalid table %q", apply.Table)
		}
		if apply.RulePriority != "" {
			priority, err := strconv.Atoi(apply.RulePriority)
			if err != nil || priority < 1 || priority > 32765 {
				return c, fmt.Errorf("invalid rule_priority %q", apply.RulePriority)
			}
		}
		if apply.Mark != "" && !hexPattern.MatchString(apply.Mark) {
			return c, fmt.Errorf("invalid mark %q", apply.Mark)
		}
		if apply.Mask != "" && !hexPattern.MatchString(apply.Mask) {
			return c, fmt.Errorf("invalid mask %q", apply.Mask)
		}
		if apply.NextHop != "" && (net.ParseIP(apply.NextHop) == nil || net.ParseIP(apply.NextHop).To4() == nil) {
			return c, fmt.Errorf("invalid next_hop %q", apply.NextHop)
		}
		if apply.SourceNet != "" && !validIPv4CIDR(apply.SourceNet) {
			return c, fmt.Errorf("invalid source_net %q", apply.SourceNet)
		}
		for _, network := range apply.BaseAllowed {
			if !validIPv4CIDR(network) {
				return c, fmt.Errorf("invalid base_allowed network %q", network)
			}
		}
		switch apply.Driver {
		case "wg-route":
			if apply.Interface == "" || apply.Peer == "" {
				return c, fmt.Errorf("wg-route requires interface and peer")
			}
		case "linux-edge":
			if apply.Interface == "" || apply.Peer == "" || apply.SourceNet == "" {
				return c, fmt.Errorf("linux-edge requires interface, peer, and source_net")
			}
		case "openwrt-pbr":
			if apply.PBRSection == "" || apply.FirewallSection == "" || !identifierPattern.MatchString(apply.PBRSection) || !identifierPattern.MatchString(apply.FirewallSection) {
				return c, fmt.Errorf("openwrt-pbr requires pbr_section and firewall_section")
			}
		case "linux-exit", "nft-exit":
			if apply.SourceNet == "" || apply.WANInterface == "" {
				return c, fmt.Errorf("%s requires source_net and wan_interface", apply.Driver)
			}
		default:
			return c, fmt.Errorf("unsupported apply driver %q", apply.Driver)
		}
	}
	return c, nil
}

func validHostPort(value string) bool {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || port == "" {
		return false
	}
	valuePort, err := strconv.Atoi(port)
	return err == nil && valuePort > 0 && valuePort <= 65535 && net.ParseIP(host) != nil
}

func validIPv4CIDR(value string) bool {
	ip, _, err := net.ParseCIDR(value)
	return err == nil && ip.To4() != nil
}

func (c Config) PollInterval() (time.Duration, error) {
	if c.Interval == "" {
		return 30 * time.Second, nil
	}
	d, err := time.ParseDuration(c.Interval)
	if err != nil || d < 5*time.Second {
		return 0, fmt.Errorf("interval must be at least 5s")
	}
	return d, nil
}
