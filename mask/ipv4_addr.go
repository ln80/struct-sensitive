package mask

import (
	"fmt"
	"net"
	"strings"

	"github.com/ln80/struct-sensitive/internal/option"
)

type IPv4AddrConfig struct {
	OctetsToMask   int  // default 1
	OneOctetSymbol bool // default false
}

// IPv4Addr masks the last octet by default and leaves the rest of the address visible.
// The visible prefix can still locate a network. Raise OctetsToMask to hide more of it.
// OctetsToMask must be from 0 through 4. Zero leaves the address unchanged.
func IPv4Addr(ip string, opts ...func(*Config[IPv4AddrConfig])) (string, error) {
	cfg := DefaultConfig(IPv4AddrConfig{
		OctetsToMask: 1,
	})
	option.Apply(&cfg, opts)
	if cfg.Kind.OctetsToMask < 0 || cfg.Kind.OctetsToMask > 4 {
		return "", fmt.Errorf("octets to mask must be between 0 and 4")
	}

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
	mustRegister("ipv4_addr", DefaultMasker(IPv4Addr))
}
