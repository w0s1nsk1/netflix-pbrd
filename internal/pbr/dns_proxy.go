package pbr

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var defaultNetflixSuffixes = []string{
	"netflix.com",
	"netflix.net",
	"nflxext.com",
	"nflximg.com",
	"nflximg.net",
	"nflxsearch.net",
	"nflxso.net",
	"nflxvideo.net",
}

var defaultNetflixServicePrefixes = []string{
	"apiproxy-device-prod-",
	"pushy-prod-",
}

type dnsLearner struct {
	config  DNSProxyConfig
	learn   func(context.Context, []string) error
	mu      sync.RWMutex
	aliases map[string]struct{}
}

func newDNSLearner(config DNSProxyConfig, learn func(context.Context, []string) error) *dnsLearner {
	if len(config.TrustedSuffixes) == 0 {
		config.TrustedSuffixes = append([]string(nil), defaultNetflixSuffixes...)
	}
	if len(config.ServicePrefixes) == 0 {
		config.ServicePrefixes = append([]string(nil), defaultNetflixServicePrefixes...)
	}
	return &dnsLearner{config: config, learn: learn, aliases: make(map[string]struct{})}
}

func (l *dnsLearner) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	upstreamRequest := request.Copy()
	addClientSubnet(upstreamRequest, w.RemoteAddr())
	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	response, _, err := client.Exchange(upstreamRequest, l.config.Upstream)
	if err == nil && response.Truncated {
		client.Net = "tcp"
		response, _, err = client.Exchange(upstreamRequest, l.config.Upstream)
	}
	if err != nil {
		failure := new(dns.Msg)
		failure.SetRcode(request, dns.RcodeServerFailure)
		_ = w.WriteMsg(failure)
		log.Printf("dns proxy upstream: %v", err)
		return
	}
	networks := l.inspect(response)
	if len(networks) > 0 && l.learn != nil {
		if err := l.learn(context.Background(), networks); err != nil {
			log.Printf("dns learn: %v", err)
		}
	}
	if err := w.WriteMsg(response); err != nil {
		log.Printf("dns proxy response: %v", err)
	}
}

func addClientSubnet(message *dns.Msg, remote net.Addr) {
	if remote == nil {
		return
	}
	host, _, err := net.SplitHostPort(remote.String())
	if err != nil {
		return
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return
	}
	opt := message.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232}}
		message.Extra = append(message.Extra, opt)
	}
	options := opt.Option[:0]
	for _, option := range opt.Option {
		if option.Option() != dns.EDNS0SUBNET {
			options = append(options, option)
		}
	}
	opt.Option = append(options, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 32,
		Address:       ip,
	})
}

func (l *dnsLearner) inspect(message *dns.Msg) []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	trusted := make(map[string]struct{}, len(l.aliases)+len(message.Question))
	for name := range l.aliases {
		trusted[name] = struct{}{}
	}
	for _, question := range message.Question {
		name := canonicalDNSName(question.Name)
		if l.isNetflixName(name) {
			trusted[name] = struct{}{}
		}
	}

	records := append(append([]dns.RR(nil), message.Answer...), message.Extra...)
	for changed := true; changed; {
		changed = false
		for _, record := range records {
			cname, ok := record.(*dns.CNAME)
			if !ok {
				continue
			}
			owner := canonicalDNSName(cname.Hdr.Name)
			target := canonicalDNSName(cname.Target)
			if _, ok := trusted[owner]; ok {
				if _, exists := trusted[target]; !exists {
					trusted[target] = struct{}{}
					l.aliases[target] = struct{}{}
					changed = true
				}
			}
		}
	}

	var values []string
	for _, record := range records {
		a, ok := record.(*dns.A)
		if !ok {
			continue
		}
		if _, ok := trusted[canonicalDNSName(a.Hdr.Name)]; ok {
			values = append(values, a.A.String())
		}
	}
	return Merge(values)
}

func (l *dnsLearner) isNetflixName(name string) bool {
	for _, suffix := range l.config.TrustedSuffixes {
		suffix = canonicalDNSName(suffix)
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	if !strings.HasSuffix(name, ".amazonaws.com") || !strings.Contains(name, ".elb.") {
		return false
	}
	label := strings.SplitN(name, ".", 2)[0]
	for _, prefix := range l.config.ServicePrefixes {
		if strings.HasPrefix(label, strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}

func canonicalDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func startDNSProxy(ctx context.Context, config DNSProxyConfig, learn func(context.Context, []string) error) error {
	udp, err := net.ListenPacket("udp", config.Listen)
	if err != nil {
		return fmt.Errorf("dns proxy udp: %v", err)
	}
	tcp, err := net.Listen("tcp", config.Listen)
	if err != nil {
		_ = udp.Close()
		return fmt.Errorf("dns proxy tcp: %v", err)
	}
	handler := newDNSLearner(config, learn)
	udpServer := &dns.Server{PacketConn: udp, Handler: handler}
	tcpServer := &dns.Server{Listener: tcp, Handler: handler}
	go func() {
		if err := udpServer.ActivateAndServe(); err != nil && ctx.Err() == nil {
			log.Printf("dns proxy udp: %v", err)
		}
	}()
	go func() {
		if err := tcpServer.ActivateAndServe(); err != nil && ctx.Err() == nil {
			log.Printf("dns proxy tcp: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	}()
	log.Printf("dns learning proxy listening on %s via %s", config.Listen, config.Upstream)
	return nil
}
