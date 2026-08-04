package pbr

import (
	"bufio"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	if err != nil || ip.To4() == nil || !isPublicIPv4(ip) {
		return "", false
	}
	return network.String(), true
}

func isPublicIPv4(ip net.IP) bool {
	v := ip.To4()
	if v == nil || v[0] == 0 || v[0] == 10 || v[0] == 127 || v[0] >= 224 {
		return false
	}
	if v[0] == 169 && v[1] == 254 || v[0] == 192 && v[1] == 168 || v[0] == 172 && v[1] >= 16 && v[1] <= 31 {
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
	return Merge(values), s.Err()
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
