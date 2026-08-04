package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/w0s1nsk1/netflix-pbrd/internal/pbr"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		if err := runCommand(os.Args[1], os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	runDaemon(os.Args[1:])
}

func runDaemon(args []string) {
	flags := flag.NewFlagSet("netflix-pbrd", flag.ExitOnError)
	configPath := flags.String("config", "/etc/netflix-pbrd.json", "path to JSON configuration")
	showVersion := flags.Bool("version", false, "print version")
	checkConfig := flags.Bool("check", false, "validate configuration and exit")
	_ = flags.Parse(args)
	if *showVersion {
		fmt.Println(version)
		return
	}
	config, err := pbr.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *checkConfig {
		fmt.Println("configuration is valid")
		return
	}
	runtime, err := pbr.NewRuntime(config)
	if err != nil {
		log.Fatalf("runtime: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() { <-signals; cancel() }()
	log.Printf("netflix-pbrd %s starting as %s", version, config.Role)
	if err := runtime.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

func runCommand(command string, args []string) error {
	switch command {
	case "generate":
		return generateCommand(args)
	case "install":
		return installCommand(args)
	case "doctor":
		return doctorCommand(args)
	case "status":
		return statusCommand(args)
	case "smoke-test":
		return smokeCommand(args)
	case "cleanup":
		return cleanupCommand(args)
	case "uninstall":
		return uninstallCommand(args)
	case "version":
		fmt.Println(version)
		return nil
	case "help":
		printHelp()
		return nil
	default:
		return fmt.Errorf("unknown command %q; use generate, install, doctor, status, smoke-test, cleanup, or uninstall", command)
	}
}

func printHelp() {
	fmt.Println(`netflix-pbrd commands:
  generate    create a recommended nested edge+exit config bundle
  install     install this binary and one generated config
  doctor      verify interfaces, API, DNS, firewall, routes, and reporting
  status      show learned -> applied -> reported and the last error
  smoke-test  resolve Netflix through the proxy and verify the selected route
  cleanup     remove only networking state owned by configured drivers
  uninstall   stop the service, clean networking state, and remove the binary`)
}

func generateCommand(args []string) error {
	flags := flag.NewFlagSet("generate", flag.ContinueOnError)
	topology := flags.String("topology", "nested", "topology to generate")
	output := flags.String("output", "netflix-pbrd-bundle", "output directory")
	edgePeer := flags.String("edge-peer", "", "exit WireGuard public key used by edge")
	sourceNet := flags.String("source-net", "192.168.8.0/24", "application LAN network")
	wan := flags.String("exit-wan", "wan", "exit WAN interface")
	tunnel := flags.String("tunnel-interface", "wg-relay", "edge WireGuard interface")
	input := flags.String("input-interface", "br+", "edge LAN input interface")
	controllerListen := flags.String("controller-listen", "172.31.255.1:18080", "controller API listen address")
	controllerURL := flags.String("controller-url", "http://172.31.255.1:18080", "controller URL reachable by edge")
	dnsListen := flags.String("dns-listen", "192.168.8.2:1053", "edge DNS proxy address")
	dnsUpstream := flags.String("dns-upstream", "10.8.0.1:53", "upstream DNS address")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *topology != "nested" {
		return fmt.Errorf("only the recommended nested topology is generated; advanced examples are in configs/")
	}
	err := pbr.GenerateNestedBundle(pbr.NestedBundleOptions{OutputDir: *output, EdgePeer: *edgePeer, SourceNet: *sourceNet, ExitWAN: *wan, TunnelInterface: *tunnel, InputInterface: *input, ControllerListen: *controllerListen, ControllerURL: *controllerURL, DNSListen: *dnsListen, DNSUpstream: *dnsUpstream})
	if err == nil {
		fmt.Printf("generated %s/edge.json and %s/exit.json\n", *output, *output)
	}
	return err
}

func installCommand(args []string) error {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	configPath := flags.String("config", "", "generated edge.json or exit.json")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		return fmt.Errorf("install requires -config")
	}
	layout, err := pbr.InstallSelf(*configPath, pbr.ExecRunner{})
	if err == nil {
		fmt.Printf("installed on %s: %s -config %s\n", layout.Platform, layout.Binary, layout.Config)
	}
	return err
}

func doctorCommand(args []string) error {
	config, err := commandConfig("doctor", args)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	failed := 0
	for _, check := range pbr.Doctor(ctx, config, pbr.ExecRunner{}) {
		state := "ok"
		if !check.OK {
			state = "FAIL"
			failed++
		}
		fmt.Printf("%-4s  %-22s %s\n", state, check.Name, check.Detail)
	}
	if failed > 0 {
		return fmt.Errorf("doctor found %d failed checks", failed)
	}
	return nil
}

func statusCommand(args []string) error {
	config, err := commandConfig("status", args)
	if err != nil {
		return err
	}
	status, err := pbr.LoadOperationalStatus(pbr.RuntimeStatusFile(config.StateFile))
	if err != nil {
		return err
	}
	fmt.Printf("role: %s\nlearned -> applied -> reported: %d -> %d -> %d\ndesired: %d\nlast apply: %s\nlast report: %s\n", status.Role, status.Learned, status.Applied, status.Reported, status.Desired, formatTime(status.LastApply), formatTime(status.LastReport))
	if status.LastError != "" {
		fmt.Printf("last error: %s (%s)\n", status.LastError, formatTime(status.LastErrorAt))
	}
	return nil
}

func smokeCommand(args []string) error {
	flags := flag.NewFlagSet("smoke-test", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "configuration path")
	name := flags.String("name", "android.prod.cloud.netflix.com.", "trusted Netflix DNS name")
	if err := flags.Parse(args); err != nil {
		return err
	}
	config, err := pbr.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	result, err := pbr.SmokeTest(config, pbr.ExecRunner{}, *name)
	if err != nil {
		return err
	}
	fmt.Printf("DNS: %s -> %s\nlearned -> applied -> reported: %s\nroute: %s\nconfirmed: %t\n", result.Name, strings.Join(result.Addresses, ", "), result.Progress, result.Route, result.Confirmed)
	return nil
}

func cleanupCommand(args []string) error {
	config, err := commandConfig("cleanup", args)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("cleanup must run as root")
	}
	if err := pbr.Cleanup(config, pbr.ExecRunner{}); err != nil {
		return err
	}
	fmt.Println("owned networking state removed; service and files were preserved")
	return nil
}

func uninstallCommand(args []string) error {
	flags := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "configuration path")
	purge := flags.Bool("purge", false, "also remove configuration and learned state")
	yes := flags.Bool("yes", false, "confirm cleanup and uninstall")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*yes {
		return fmt.Errorf("uninstall requires -yes; configuration is preserved unless -purge is set")
	}
	layout, err := pbr.Uninstall(*configPath, *purge, pbr.ExecRunner{})
	if err == nil {
		fmt.Printf("removed %s installation and owned networking state\n", layout.Platform)
	}
	return err
}

func commandConfig(name string, args []string) (pbr.Config, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "configuration path")
	if err := flags.Parse(args); err != nil {
		return pbr.Config{}, err
	}
	return pbr.LoadConfig(*configPath)
}

func defaultConfigPath() string {
	return pbr.DetectInstallLayout().Config
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return "never"
	}
	return value.Local().Format(time.RFC3339)
}
