package pbr

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type APIResponse struct {
	Version  int      `json:"version"`
	Updated  string   `json:"updated"`
	Networks []string `json:"networks"`
}

type Runtime struct {
	config   Config
	interval time.Duration
	syncMu   sync.Mutex
	mu       sync.RWMutex
	networks []string
	updated  time.Time
}

func NewRuntime(c Config) (*Runtime, error) {
	interval, err := c.PollInterval()
	if err != nil {
		return nil, err
	}
	state, err := LoadState(c.StateFile)
	if err != nil {
		return nil, err
	}
	groups := [][]string{state, c.SeedNetworks}
	for _, apply := range c.Apply {
		if (apply.Driver == "wg-route" || apply.Driver == "linux-edge") && apply.Interface != "" && apply.Peer != "" {
			if current, readErr := currentWGNetworks(apply.Interface, apply.Peer); readErr == nil {
				groups = append(groups, current)
			}
		}
	}
	return &Runtime{config: c, interval: interval, networks: Merge(groups...), updated: time.Now().UTC()}, nil
}

func (r *Runtime) Run(ctx context.Context) error {
	if r.config.API.Listen != "" {
		go r.serve(ctx)
	}
	if err := r.sync(ctx, true); err != nil {
		log.Printf("initial sync: %v", err)
	}
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := r.sync(ctx, false); err != nil {
				log.Printf("sync: %v", err)
			}
		}
	}
}

func (r *Runtime) sync(ctx context.Context, force bool) error {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	var discovered []string
	var err error
	if r.config.Role == "controller" {
		discovered, err = r.resolve(ctx)
	} else {
		discovered, err = r.fetch(ctx)
	}
	if err != nil {
		return err
	}
	r.mu.RLock()
	previous := append([]string(nil), r.networks...)
	r.mu.RUnlock()
	next := Merge(previous, discovered, r.config.SeedNetworks)
	if len(next) == 0 {
		return fmt.Errorf("empty network set")
	}
	if !force && Equal(previous, next) {
		return nil
	}
	for _, apply := range r.config.Apply {
		if err := applyNetworks(apply, next); err != nil {
			return fmt.Errorf("apply %s: %v", apply.Driver, err)
		}
	}
	if err := SaveState(r.config.StateFile, next); err != nil {
		return err
	}
	r.mu.Lock()
	r.networks, r.updated = next, time.Now().UTC()
	r.mu.Unlock()
	if r.config.Role == "agent" {
		if err := r.report(ctx, next); err != nil {
			log.Printf("report: %v", err)
		}
	}
	log.Printf("applied %d networks", len(next))
	return nil
}

func (r *Runtime) resolve(ctx context.Context) ([]string, error) {
	resolver := net.DefaultResolver
	if r.config.Discovery.DNSServer != "" {
		resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", r.config.Discovery.DNSServer)
		}}
	}
	var values []string
	for _, domain := range r.config.Discovery.Domains {
		ips, err := resolver.LookupIPAddr(ctx, domain)
		if err != nil {
			log.Printf("resolve %s: %v", domain, err)
			continue
		}
		for _, item := range ips {
			if item.IP.To4() != nil {
				values = append(values, item.IP.String())
			}
		}
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("no domains resolved")
	}
	return Merge(values), nil
}

func (r *Runtime) fetch(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.config.API.SourceURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+r.config.API.Token)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("controller returned %s", resp.Status)
	}
	var payload APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return Merge(payload.Networks), nil
}

func (r *Runtime) report(ctx context.Context, networks []string) error {
	payload, err := json.Marshal(APIResponse{Version: 1, Networks: networks})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.config.API.SourceURL, strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.config.API.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("controller returned %s", resp.Status)
	}
	return nil
}

func (r *Runtime) acceptReport(networks []string) error {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	r.mu.RLock()
	previous := append([]string(nil), r.networks...)
	r.mu.RUnlock()
	next := Merge(previous, networks)
	if Equal(previous, next) {
		return nil
	}
	for _, apply := range r.config.Apply {
		if err := applyNetworks(apply, next); err != nil {
			return err
		}
	}
	if err := SaveState(r.config.StateFile, next); err != nil {
		return err
	}
	r.mu.Lock()
	r.networks, r.updated = next, time.Now().UTC()
	r.mu.Unlock()
	log.Printf("accepted agent report; applied %d networks", len(next))
	return nil
}

func (r *Runtime) serve(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/networks", func(w http.ResponseWriter, req *http.Request) {
		provided := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(r.config.API.Token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch req.Method {
		case http.MethodGet:
			r.mu.RLock()
			payload := APIResponse{Version: 1, Updated: r.updated.Format(time.RFC3339), Networks: append([]string(nil), r.networks...)}
			r.mu.RUnlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(payload)
		case http.MethodPost:
			if r.config.Role != "controller" {
				http.Error(w, "reports require controller role", http.StatusMethodNotAllowed)
				return
			}
			req.Body = http.MaxBytesReader(w, req.Body, 1024*1024)
			var payload APIResponse
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil || len(payload.Networks) > 4096 {
				http.Error(w, "invalid report", http.StatusBadRequest)
				return
			}
			if err := r.acceptReport(payload.Networks); err != nil {
				log.Printf("agent report: %v", err)
				http.Error(w, "apply failed", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	server := &http.Server{Addr: r.config.API.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	var err error
	if r.config.API.TLSCert != "" {
		err = server.ListenAndServeTLS(r.config.API.TLSCert, r.config.API.TLSKey)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Printf("api server: %v", err)
	}
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runInput(input, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func routeBatch(lines []string) error {
	if len(lines) == 0 {
		return nil
	}
	return runInput(strings.Join(lines, "\n")+"\n", "ip", "-force", "-batch", "-")
}

func restoreMangle(input string) error {
	if path, err := exec.LookPath("iptables-restore"); err == nil {
		return runInput(input, path, "--noflush")
	}
	if _, err := os.Stat("/system/bin/xtables-multi"); err == nil {
		return runInput(input, "/system/bin/xtables-multi", "iptables-restore", "--noflush")
	}
	return fmt.Errorf("iptables-restore not found")
}

func runIgnore(name string, args ...string)     { _ = run(name, args...) }
func succeeds(name string, args ...string) bool { return run(name, args...) == nil }

func currentWGNetworks(iface, peer string) ([]string, error) {
	out, err := exec.Command("wg", "show", iface, "allowed-ips").Output()
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && fields[0] == peer {
			return Merge(fields[1:]), nil
		}
	}
	return nil, fmt.Errorf("peer %s not found on %s", peer, iface)
}

func applyNetworks(c ApplyConfig, nets []string) error {
	switch c.Driver {
	case "wg-route":
		return applyWGRoute(c, nets)
	case "linux-edge":
		return applyEdge(c, nets)
	case "openwrt-pbr":
		return applyOpenWrt(c, nets)
	case "linux-exit":
		return applyExit(c, nets)
	default:
		return fmt.Errorf("unknown driver %q", c.Driver)
	}
}

func allowed(c ApplyConfig, nets []string) string {
	for _, base := range c.BaseAllowed {
		if base == "0.0.0.0/0" {
			return strings.Join(c.BaseAllowed, ",")
		}
	}
	return strings.Join(append(append([]string{}, c.BaseAllowed...), nets...), ",")
}

func replaceIPRule(priority, mark, mask, table string) error {
	for succeeds("ip", "rule", "del", "pref", priority) {
	}
	return run("ip", "rule", "add", "pref", priority, "fwmark", mark+"/"+mask, "lookup", table)
}

func applyWGRoute(c ApplyConfig, nets []string) error {
	if c.Interface == "" || c.Peer == "" {
		return fmt.Errorf("interface and peer are required")
	}
	if err := run("wg", "set", c.Interface, "peer", c.Peer, "allowed-ips", allowed(c, nets)); err != nil {
		return err
	}
	lines := make([]string, 0, len(nets))
	for _, n := range nets {
		lines = append(lines, "route replace "+n+" dev "+c.Interface)
	}
	return routeBatch(lines)
}

func applyEdge(c ApplyConfig, nets []string) error {
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
	if err := run("wg", "set", c.Interface, "peer", c.Peer, "allowed-ips", allowed(c, nets)); err != nil {
		return err
	}
	routeTarget := "dev " + c.Interface
	if c.NextHop != "" {
		routeTarget = "via " + c.NextHop + " " + routeTarget
	}
	routes := []string{"route replace default " + routeTarget + " table " + c.Table}
	for _, n := range nets {
		routes = append(routes, "route replace "+n+" "+routeTarget)
	}
	if err := routeBatch(routes); err != nil {
		return err
	}
	if err := replaceIPRule(c.RulePriority, c.Mark, c.Mask, c.Table); err != nil {
		return err
	}
	runIgnore("iptables", "-t", "mangle", "-N", c.Chain)
	if !succeeds("iptables", "-t", "mangle", "-C", "PREROUTING", "-i", "br+", "-s", c.SourceNet, "-j", c.Chain) {
		runIgnore("iptables", "-t", "mangle", "-I", "PREROUTING", "1", "-i", "br+", "-s", c.SourceNet, "-j", c.Chain)
	}
	var restore strings.Builder
	restore.WriteString("*mangle\n-F " + c.Chain + "\n")
	for _, n := range nets {
		restore.WriteString("-A " + c.Chain + " -d " + n + " -j MARK --set-mark " + c.Mark + "\n")
	}
	restore.WriteString("COMMIT\n")
	return restoreMangle(restore.String())
}

func applyOpenWrt(c ApplyConfig, nets []string) error {
	if c.PBRSection == "" || c.FirewallSection == "" {
		return fmt.Errorf("pbr_section and firewall_section are required")
	}
	if err := run("uci", "set", "pbr."+c.PBRSection+".dest_addr="+strings.Join(nets, " ")); err != nil {
		return err
	}
	runIgnore("uci", "-q", "delete", "firewall."+c.FirewallSection+".dest_ip")
	for _, n := range nets {
		if err := run("uci", "add_list", "firewall."+c.FirewallSection+".dest_ip="+n); err != nil {
			return err
		}
	}
	if err := run("uci", "commit", "pbr"); err != nil {
		return err
	}
	if err := run("uci", "commit", "firewall"); err != nil {
		return err
	}
	if err := run("/etc/init.d/firewall", "reload"); err != nil {
		return err
	}
	return run("/etc/init.d/pbr", "reload")
}

func applyExit(c ApplyConfig, nets []string) error {
	if c.Chain == "" {
		c.Chain = "STREAM_EXIT"
	}
	runIgnore("iptables", "-N", c.Chain)
	if err := run("iptables", "-F", c.Chain); err != nil {
		return err
	}
	if err := run("iptables", "-A", c.Chain, "-d", c.SourceNet, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return err
	}
	for _, n := range nets {
		if err := run("iptables", "-A", c.Chain, "-s", c.SourceNet, "-d", n, "-j", "ACCEPT"); err != nil {
			return err
		}
	}
	if !succeeds("iptables", "-C", "FORWARD", "-j", c.Chain) {
		runIgnore("iptables", "-I", "FORWARD", "1", "-j", c.Chain)
	}
	if !succeeds("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", c.SourceNet, "-o", c.WANInterface, "-j", "MASQUERADE") {
		runIgnore("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", c.SourceNet, "-o", c.WANInterface, "-j", "MASQUERADE")
	}
	return nil
}
