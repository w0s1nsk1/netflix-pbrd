package pbr

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSProxyForwardsUDPAndTCPBeforeLearningReturns(t *testing.T) {
	upstreamTCP, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("network namespace does not allow listeners: %v", err)
	}
	upstreamUDP, err := net.ListenPacket("udp", upstreamTCP.Addr().String())
	if err != nil {
		upstreamTCP.Close()
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		opt := request.IsEdns0()
		if opt == nil || len(opt.Option) != 1 {
			t.Errorf("missing ECS option: %#v", opt)
		} else if subnet, ok := opt.Option[0].(*dns.EDNS0_SUBNET); !ok || subnet.Address.String() != "127.0.0.1" || subnet.SourceNetmask != 32 {
			t.Errorf("invalid ECS option: %#v", opt.Option[0])
		}
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("45.57.22.134"),
		}}
		_ = w.WriteMsg(response)
	})
	upstreamUDPServer := &dns.Server{PacketConn: upstreamUDP, Handler: handler}
	upstreamTCPServer := &dns.Server{Listener: upstreamTCP, Handler: handler}
	go upstreamUDPServer.ActivateAndServe()
	go upstreamTCPServer.ActivateAndServe()
	defer upstreamUDPServer.Shutdown()
	defer upstreamTCPServer.Shutdown()

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddress := probe.Addr().String()
	probe.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	learned := make(chan []string, 2)
	if err := startDNSProxy(ctx, DNSProxyConfig{Listen: proxyAddress, Upstream: upstreamTCP.Addr().String()}, func(_ context.Context, networks []string) error {
		learned <- networks
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	for _, network := range []string{"udp", "tcp"} {
		request := new(dns.Msg)
		request.SetQuestion("ios27.appboot.netflix.com.", dns.TypeA)
		response, _, err := (&dns.Client{Net: network, Timeout: time.Second}).Exchange(request, proxyAddress)
		if err != nil {
			t.Fatalf("%s exchange: %v", network, err)
		}
		if len(response.Answer) != 1 {
			t.Fatalf("%s answers=%d", network, len(response.Answer))
		}
		select {
		case got := <-learned:
			if !Equal(got, []string{"45.57.22.134/32"}) {
				t.Fatalf("%s learned %v", network, got)
			}
		default:
			t.Fatalf("%s response returned before learning callback", network)
		}
	}
}

func TestAddClientSubnetPreservesOtherEDNSOptionsAndReplacesECS(t *testing.T) {
	message := new(dns.Msg)
	message.SetQuestion("android.prod.cloud.netflix.com.", dns.TypeA)
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096}}
	opt.Option = []dns.EDNS0{
		&dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "test"},
		&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("192.0.2.0")},
	}
	message.Extra = append(message.Extra, opt)
	addClientSubnet(message, &net.UDPAddr{IP: net.ParseIP("192.168.8.230"), Port: 53000})
	if len(opt.Option) != 2 {
		t.Fatalf("options=%#v", opt.Option)
	}
	subnet, ok := opt.Option[1].(*dns.EDNS0_SUBNET)
	if !ok || subnet.Address.String() != "192.168.8.230" || subnet.SourceNetmask != 32 {
		t.Fatalf("subnet=%#v", opt.Option[1])
	}
}

func TestDNSLearnerRecognizesFutureNetflixAppNames(t *testing.T) {
	learner := newDNSLearner(DNSProxyConfig{}, nil)
	for _, name := range []string{
		"ios27.appboot.netflix.com.",
		"android15-tman.prod.cloud.netflix.com.",
		"ipv4-c012-fra001-ix.1.oca.nflxvideo.net.",
	} {
		message := dnsMessage(name, name, "45.57.22.134")
		if got := learner.inspect(message); !Equal(got, []string{"45.57.22.134/32"}) {
			t.Fatalf("%s learned %v", name, got)
		}
	}
}

func TestDNSLearnerFollowsTrustedCNAME(t *testing.T) {
	learner := newDNSLearner(DNSProxyConfig{}, nil)
	message := new(dns.Msg)
	message.SetQuestion("api-global.netflix.com.", dns.TypeA)
	message.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "api-global.netflix.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "service.us-east-1.elb.amazonaws.com."},
		&dns.A{Hdr: dns.RR_Header{Name: "service.us-east-1.elb.amazonaws.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("54.84.54.3")},
	}
	if got := learner.inspect(message); !Equal(got, []string{"54.84.54.3/32"}) {
		t.Fatalf("learned %v", got)
	}

	aliasQuery := dnsMessage("service.us-east-1.elb.amazonaws.com.", "service.us-east-1.elb.amazonaws.com.", "98.85.45.78")
	if got := learner.inspect(aliasQuery); !Equal(got, []string{"98.85.45.78/32"}) {
		t.Fatalf("remembered alias learned %v", got)
	}
}

func TestDNSLearnerLimitsDirectServicePrefixesToAWSLoadBalancers(t *testing.T) {
	learner := newDNSLearner(DNSProxyConfig{}, nil)
	trusted := "apiproxy-device-prod-nlb-4.example.elb.us-east-1.amazonaws.com."
	if got := learner.inspect(dnsMessage(trusted, trusted, "3.220.58.77")); !Equal(got, []string{"3.220.58.77/32"}) {
		t.Fatalf("trusted service learned %v", got)
	}
	for _, name := range []string{
		"apiproxy-device-prod-evil.example.com.",
		"unrelated.elb.us-east-1.amazonaws.com.",
		"www.example.com.",
	} {
		if got := learner.inspect(dnsMessage(name, name, "8.8.8.8")); len(got) != 0 {
			t.Fatalf("untrusted %s learned %v", name, got)
		}
	}
}

func TestRuntimeLearnsAndAppliesDNSAddresses(t *testing.T) {
	runner := newFakeRunner()
	state := t.TempDir() + "/state"
	runtime, err := newRuntime(Config{
		Role:      "controller",
		StateFile: state,
		API:       APIConfig{Token: testReadToken, ReportToken: testReportToken},
		Apply:     []ApplyConfig{{Driver: "wg-route", Interface: "wg0", Peer: "peer"}},
	}, runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.learn(context.Background(), []string{"45.57.22.134"}); err != nil {
		t.Fatal(err)
	}
	if !Equal(runtime.desired, []string{"45.57.22.134/32"}) || !Equal(runtime.applied, runtime.desired) {
		t.Fatalf("desired=%v applied=%v", runtime.desired, runtime.applied)
	}
	stateNetworks, err := LoadState(state)
	if err != nil || !Equal(stateNetworks, runtime.desired) {
		t.Fatalf("state=%v err=%v", stateNetworks, err)
	}
}

func dnsMessage(question, owner, address string) *dns.Msg {
	message := new(dns.Msg)
	message.SetQuestion(question, dns.TypeA)
	message.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(address)},
	}
	return message
}
