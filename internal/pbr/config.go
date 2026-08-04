package pbr

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"time"
)

type Config struct {
	Role         string        `json:"role"`
	Interval     string        `json:"interval"`
	StateFile    string        `json:"state_file"`
	SeedNetworks []string      `json:"seed_networks"`
	API          APIConfig     `json:"api"`
	Discovery    Discovery     `json:"discovery"`
	Apply        []ApplyConfig `json:"apply"`
}

type APIConfig struct {
	Listen            string `json:"listen"`
	SourceURL         string `json:"source_url"`
	Token             string `json:"token"`
	TLSCert           string `json:"tls_cert"`
	TLSKey            string `json:"tls_key"`
	AllowInsecureHTTP bool   `json:"allow_insecure_http"`
}

type Discovery struct {
	DNSServer string   `json:"dns_server"`
	Domains   []string `json:"domains"`
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
	if c.Role == "controller" && len(c.Discovery.Domains) == 0 {
		return c, fmt.Errorf("controller requires discovery.domains")
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
	if c.Role == "controller" && c.API.Listen == "" {
		return c, fmt.Errorf("controller requires api.listen")
	}
	if c.API.Listen != "" && (c.API.TLSCert == "" || c.API.TLSKey == "") && !c.API.AllowInsecureHTTP {
		return c, fmt.Errorf("TLS is required unless allow_insecure_http is true")
	}
	for _, apply := range c.Apply {
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
			if apply.PBRSection == "" || apply.FirewallSection == "" {
				return c, fmt.Errorf("openwrt-pbr requires pbr_section and firewall_section")
			}
		case "linux-exit":
			if apply.SourceNet == "" || apply.WANInterface == "" {
				return c, fmt.Errorf("linux-exit requires source_net and wan_interface")
			}
		default:
			return c, fmt.Errorf("unsupported apply driver %q", apply.Driver)
		}
	}
	return c, nil
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
