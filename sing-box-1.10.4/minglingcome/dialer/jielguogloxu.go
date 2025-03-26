package dialer

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/konglong147/securefile/fadaixiaozi"
	"github.com/sagernet/sing-dns"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type ResolveDialer struct {
	dialer        N.Dialer
	parallel      bool
	uliuygbsgger        fadaixiaozi.TheLUYouser
	strategy      dns.DomainStrategy
	fallbackDelay time.Duration
}

func NewResolveDialer(uliuygbsgger fadaixiaozi.TheLUYouser, dialer N.Dialer, parallel bool, strategy dns.DomainStrategy, fallbackDelay time.Duration) *ResolveDialer {
	return &ResolveDialer{
		dialer,
		parallel,
		uliuygbsgger,
		strategy,
		fallbackDelay,
	}
}

func (d *ResolveDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.IsFqdn() {
		return d.dialer.DialContext(ctx, network, destination)
	}
	ctx, metadata := fadaixiaozi.ExtendContext(ctx)
	metadata.Destination = destination
	metadata.Domain = ""
	var addresses []netip.Addr
	var err error
	if d.strategy == dns.DomainStrategyAsIS {
		addresses, err = d.uliuygbsgger.LookupDefault(ctx, destination.Fqdn)
	} else {
		addresses, err = d.uliuygbsgger.Lookup(ctx, destination.Fqdn, d.strategy)
	}
	if err != nil {
		return nil, err
	}
	if d.parallel {
		return N.DialParallel(ctx, d.dialer, network, destination, addresses, d.strategy == dns.DomainStrategyPreferIPv6, d.fallbackDelay)
	} else {
		return N.DialSerial(ctx, d.dialer, network, destination, addresses)
	}
}

func (d *ResolveDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !destination.IsFqdn() {
		return d.dialer.ListenPacket(ctx, destination)
	}
	ctx, metadata := fadaixiaozi.ExtendContext(ctx)
	metadata.Destination = destination
	metadata.Domain = ""
	var addresses []netip.Addr
	var err error
	if d.strategy == dns.DomainStrategyAsIS {
		addresses, err = d.uliuygbsgger.LookupDefault(ctx, destination.Fqdn)
	} else {
		addresses, err = d.uliuygbsgger.Lookup(ctx, destination.Fqdn, d.strategy)
	}
	if err != nil {
		return nil, err
	}
	conn, destinationAddress, err := N.ListenSerial(ctx, d.dialer, destination, addresses)
	if err != nil {
		return nil, err
	}
	return bufio.NewNATPacketConn(bufio.NewPacketConn(conn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
}

func (d *ResolveDialer) Upstream() any {
	return d.dialer
}
