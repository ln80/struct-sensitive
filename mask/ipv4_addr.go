package mask

import (
	"fmt"
	"net"
	"strings"

	"github.com/ln80/struct-sensitive/option"
)

type IPv4AddrConfig struct {
	OctetsToMask   int  // default 1
	OneOctetSymbol bool // default false
}

func IPv4Addr(ip string, opts ...func(*Config[IPv4AddrConfig])) (string, error) {
	cfg := DefaultConfig(IPv4AddrConfig{
		OctetsToMask: 1,
	})
	option.Apply(&cfg, opts)

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil || strings.Contains(ip, ":") {
		return "", fmt.Errorf("invalid IPv4 address")
	}

	octets := strings.Split(ip, ".")

	oneSymbol := string([]rune{cfg.Symbol})
	threeSymbol := string([]rune{cfg.Symbol, cfg.Symbol, cfg.Symbol})
	for i := 4 - cfg.Kind.OctetsToMask; i < 4; i++ {
		if cfg.Kind.OneOctetSymbol {
			octets[i] = oneSymbol
		} else {
			octets[i] = threeSymbol
		}
	}
	return strings.Join(octets, "."), nil
}

func init() {
	Register("ipv4_addr", DefaultMasker(IPv4Addr))
}
