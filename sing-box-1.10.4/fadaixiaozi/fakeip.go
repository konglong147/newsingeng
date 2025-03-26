package fadaixiaozi

import (
	"net/netip"

	"github.com/sagernet/sing-dns"
)

type FakeIPStore interface {
	Service
	Contains(address netip.Addr) bool
	Create(domain string, isIPv6 bool) (netip.Addr, error)
	Lookup(address netip.Addr) (string, bool)
	Reset() error
}

type FakeIPStorage interface {
	FakeIPMetadata() *FakeIPMetadata
}

type FakeIPTransport interface {
	dns.Transport
	Store() FakeIPStore
}
