package pbr

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	DefaultMaxNetworks = 4096
	minimumPrefixBits  = 24
)

func CanonicalNetwork(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	if !strings.Contains(value, "/") {
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() == nil || !isPublicIPv4(ip) {
			return "", false
		}
		return ip.String() + "/32", true
	}
	ip, network, err := net.ParseCIDR(value)
	if err != nil || ip.To4() == nil {
		return "", false
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones < minimumPrefixBits || !isPublicIPv4(network.IP) || !isPublicIPv4(lastIPv4(network)) {
		return "", false
	}
	return network.String(), true
}

func lastIPv4(network *net.IPNet) net.IP {
	ip := network.IP.To4()
	last := make(net.IP, net.IPv4len)
	for i := range last {
		last[i] = ip[i] | ^network.Mask[i]
	}
	return last
}

func isPublicIPv4(ip net.IP) bool {
	v := ip.To4()
	if v == nil || v[0] == 0 || v[0] == 10 || v[0] == 127 || v[0] >= 224 {
		return false
	}
	if v[0] == 100 && v[1] >= 64 && v[1] <= 127 ||
		v[0] == 169 && v[1] == 254 ||
		v[0] == 172 && v[1] >= 16 && v[1] <= 31 ||
		v[0] == 192 && (v[1] == 0 || v[1] == 168) ||
		v[0] == 198 && (v[1] == 18 || v[1] == 19 || v[1] == 51 && v[2] == 100) ||
		v[0] == 203 && v[1] == 0 && v[2] == 113 {
		return false
	}
	return true
}

func Merge(groups ...[]string) []string {
	set := make(map[string]struct{})
	for _, group := range groups {
		for _, raw := range group {
			if value, ok := CanonicalNetwork(raw); ok {
				set[value] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func ValidateNetworks(values []string, hostsOnly bool, max int) ([]string, error) {
	if max <= 0 {
		max = DefaultMaxNetworks
	}
	set := make(map[string]struct{})
	for _, raw := range values {
		value, ok := CanonicalNetwork(raw)
		if !ok {
			return nil, fmt.Errorf("invalid public IPv4 network %q", raw)
		}
		if hostsOnly && !strings.HasSuffix(value, "/32") {
			return nil, fmt.Errorf("agent reports require /32 hosts: %q", raw)
		}
		set[value] = struct{}{}
		if len(set) > max {
			return nil, fmt.Errorf("network limit exceeded: %d", max)
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func LoadState(path string) ([]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var values []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		values = append(values, s.Text())
	}
	return values, s.Err()
}

func SaveState(path string, values []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := ioutil.WriteFile(tmp, []byte(strings.Join(values, "\n")+"\n"), 0640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func Equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
