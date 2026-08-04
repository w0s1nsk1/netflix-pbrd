package pbr

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

type NestedBundleOptions struct {
	OutputDir        string
	EdgePeer         string
	SourceNet        string
	ExitWAN          string
	TunnelInterface  string
	InputInterface   string
	ControllerListen string
	ControllerURL    string
	DNSListen        string
	DNSUpstream      string
}

func GenerateNestedBundle(options NestedBundleOptions) error {
	if options.OutputDir == "" || options.EdgePeer == "" {
		return fmt.Errorf("output directory and edge peer are required")
	}
	withNestedDefaults(&options)
	readToken, err := randomToken()
	if err != nil {
		return err
	}
	reportToken, err := randomToken()
	if err != nil {
		return err
	}
	exit := Config{
		Role:            "controller",
		Interval:        "15s",
		ReapplyInterval: "5m",
		StateFile:       "/root/netflix-pbrd/networks.state",
		API:             APIConfig{Listen: options.ControllerListen, Token: readToken, ReportToken: reportToken, AllowInsecureHTTP: true},
		Apply:           []ApplyConfig{{Driver: "nft-exit", SourceNet: options.SourceNet, WANInterface: options.ExitWAN, Chain: "netflix_exit"}},
	}
	edge := Config{
		Role:            "agent",
		Interval:        "15s",
		ReapplyInterval: "5m",
		StateFile:       "/opt/var/lib/netflix-pbrd/networks.state",
		API:             APIConfig{SourceURL: options.ControllerURL + "/v1/networks", Token: readToken, ReportToken: reportToken, AllowInsecureHTTP: true},
		DNSProxy:        DNSProxyConfig{Listen: options.DNSListen, Upstream: options.DNSUpstream},
		Apply: []ApplyConfig{{
			Driver:         "linux-edge",
			Interface:      options.TunnelInterface,
			InputInterface: options.InputInterface,
			Peer:           options.EdgePeer,
			BaseAllowed:    []string{"0.0.0.0/0"},
			SourceNet:      options.SourceNet,
			Table:          "202",
			RulePriority:   "12020",
			Mark:           "0x20000000",
			Mask:           "0xff000000",
			Chain:          "NETFLIX_PBR",
		}},
	}
	if err := os.MkdirAll(options.OutputDir, 0700); err != nil {
		return err
	}
	if err := writeConfig(filepath.Join(options.OutputDir, "exit.json"), exit); err != nil {
		return err
	}
	edgePath := filepath.Join(options.OutputDir, "edge.json")
	exitPath := filepath.Join(options.OutputDir, "exit.json")
	if err := writeConfig(edgePath, edge); err != nil {
		return err
	}
	if _, err := LoadConfig(edgePath); err != nil {
		_ = os.Remove(edgePath)
		_ = os.Remove(exitPath)
		return fmt.Errorf("generated edge config: %v", err)
	}
	if _, err := LoadConfig(exitPath); err != nil {
		_ = os.Remove(edgePath)
		_ = os.Remove(exitPath)
		return fmt.Errorf("generated exit config: %v", err)
	}
	return nil
}

func withNestedDefaults(options *NestedBundleOptions) {
	if options.SourceNet == "" {
		options.SourceNet = "192.168.8.0/24"
	}
	if options.ExitWAN == "" {
		options.ExitWAN = "wan"
	}
	if options.TunnelInterface == "" {
		options.TunnelInterface = "wg-relay"
	}
	if options.InputInterface == "" {
		options.InputInterface = "br+"
	}
	if options.ControllerListen == "" {
		options.ControllerListen = "172.31.255.1:18080"
	}
	if options.ControllerURL == "" {
		options.ControllerURL = "http://172.31.255.1:18080"
	}
	if options.DNSListen == "" {
		options.DNSListen = "192.168.8.2:1053"
	}
	if options.DNSUpstream == "" {
		options.DNSUpstream = "10.8.0.1:53"
	}
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func writeConfig(path string, config Config) error {
	b, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return ioutil.WriteFile(path, b, 0600)
}
