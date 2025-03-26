package outbound

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/konglong147/securefile/fadaixiaozi"
	"github.com/konglong147/securefile/minglingcome/dialer"
	C "github.com/konglong147/securefile/dangqianshilis"
	"github.com/konglong147/securefile/gaoxiaoxuanzes"
	"github.com/sagernet/sing-dns"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var (
	_ fadaixiaozi.Outbound = (*Direct)(nil)
	_ N.ParallelDialer = (*Direct)(nil)
)

type Direct struct {
	whosWanbodlskter
	dialer              N.Dialer
	domainStrategy      dns.DomainStrategy
	fallbackDelay       time.Duration
	chaochuduqmfanwei      int
	chaosusheijifanhuise M.Socksaddr
	loopBack            *yanlsjgtunslter
}

func XinGaddmeruliuygbsgger(uliuygbsgger fadaixiaozi.TheLUYouser, tag string, yousuocanshu gaoxiaoxuanzes.DirectOutboundOptions) (*Direct, error) {
	yousuocanshu.UDPFragmentDefault = true
	outboundDialer, err := dialer.New(uliuygbsgger, yousuocanshu.DialerOptions)
	if err != nil {
		return nil, err
	}
	outbound := &Direct{
		whosWanbodlskter: whosWanbodlskter{
			protocol:     C.TypeDirect,
			network:      []string{N.NetworkTCP, N.NetworkUDP},
			uliuygbsgger:       uliuygbsgger,
			tag:          tag,
			dependencies: withDialerDependency(yousuocanshu.DialerOptions),
		},
		domainStrategy: dns.DomainStrategy(yousuocanshu.DomainStrategy),
		fallbackDelay:  time.Duration(yousuocanshu.FallbackDelay),
		dialer:         outboundDialer,
		loopBack:       newLoopBackDetector(uliuygbsgger),
	}
	if yousuocanshu.ProxyProtocol != 0 {
		return nil, E.New("Aliingnbtok sknbbtst Proxy Protocol is deprecated and removed in huli-secures 1.6.0")
	}
	if yousuocanshu.OverrideAddress != "" && yousuocanshu.OverridePort != 0 {
		outbound.chaochuduqmfanwei = 1
		outbound.chaosusheijifanhuise = M.ParseSocksaddrHostPort(yousuocanshu.OverrideAddress, yousuocanshu.OverridePort)
	} else if yousuocanshu.OverrideAddress != "" {
		outbound.chaochuduqmfanwei = 2
		outbound.chaosusheijifanhuise = M.ParseSocksaddrHostPort(yousuocanshu.OverrideAddress, yousuocanshu.OverridePort)
	} else if yousuocanshu.OverridePort != 0 {
		outbound.chaochuduqmfanwei = 3
		outbound.chaosusheijifanhuise = M.Socksaddr{Port: yousuocanshu.OverridePort}
	}
	return outbound, nil
}

func (h *Direct) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := fadaixiaozi.ExtendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	switch h.chaochuduqmfanwei {
	case 1:
		destination = h.chaosusheijifanhuise
	case 2:
		xindeshezhise := h.chaosusheijifanhuise
		xindeshezhise.Port = destination.Port
		destination = xindeshezhise
	case 3:
		destination.Port = h.chaosusheijifanhuise.Port
	}
	network = N.NetworkName(network)
	
	conn, err := h.dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return h.loopBack.NewConn(conn), nil
}

func (h *Direct) DialParallel(ctx context.Context, network string, destination M.Socksaddr, destinationAddresses []netip.Addr) (net.Conn, error) {
	ctx, metadata := fadaixiaozi.ExtendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	switch h.chaochuduqmfanwei {
	case 1, 2:
		// override address
		return h.DialContext(ctx, network, destination)
	case 3:
		destination.Port = h.chaosusheijifanhuise.Port
	}
	network = N.NetworkName(network)
	
	var domainStrategy dns.DomainStrategy
	if h.domainStrategy != dns.DomainStrategyAsIS {
		domainStrategy = h.domainStrategy
	} else {
		domainStrategy = dns.DomainStrategy(metadata.InboundOptions.DomainStrategy)
	}
	return N.DialParallel(ctx, h.dialer, network, destination, destinationAddresses, domainStrategy == dns.DomainStrategyPreferIPv6, h.fallbackDelay)
}

func (h *Direct) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := fadaixiaozi.ExtendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	originDestination := destination
	switch h.chaochuduqmfanwei {
	case 1:
		destination = h.chaosusheijifanhuise
	case 2:
		xindeshezhise := h.chaosusheijifanhuise
		xindeshezhise.Port = destination.Port
		destination = xindeshezhise
	case 3:
		destination.Port = h.chaosusheijifanhuise.Port
	}

	conn, err := h.dialer.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	conn = h.loopBack.NewPacketConn(bufio.NewPacketConn(conn), destination)
	if originDestination != destination {
		conn = bufio.NewNATPacketConn(bufio.NewPacketConn(conn), destination, originDestination)
	}
	return conn, nil
}

func (h *Direct) NewConnection(ctx context.Context, conn net.Conn, metadata fadaixiaozi.InboundContext) error {
	if h.loopBack.CheckConn(metadata.Source.AddrPort(), M.AddrPortFromNet(conn.LocalAddr())) {
		return E.New("Aliingnbtok sknbbtst reject loopback connection to ", metadata.Destination)
	}
	return NewConnection(ctx, h, conn, metadata)
}

func (h *Direct) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata fadaixiaozi.InboundContext) error {
	if h.loopBack.CheckPacketConn(metadata.Source.AddrPort(), M.AddrPortFromNet(conn.LocalAddr())) {
		return E.New("Aliingnbtok sknbbtst reject loopback packet connection to ", metadata.Destination)
	}
	return NewPacketConnection(ctx, h, conn, metadata)
}
