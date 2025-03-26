package outbound

import (
	"context"
	"net"

	"github.com/konglong147/securefile/fadaixiaozi"
	"github.com/konglong147/securefile/minglingcome/dialer"
	"github.com/konglong147/securefile/minglingcome/mux"
	"github.com/konglong147/securefile/minglingcome/tls"
	C "github.com/konglong147/securefile/dangqianshilis"
	"github.com/konglong147/securefile/log"
	"github.com/konglong147/securefile/gaoxiaoxuanzes"

	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

var _ fadaixiaozi.Outbound = (*VMess)(nil)

type VMess struct {
	whosWanbodlskter
	dialer          N.Dialer
	client          *vmess.Client
	fuwuseradds      M.Socksaddr
	hunklunasler *mux.Client
	Slgservconsger       tls.Config
	transport       fadaixiaozi.V2RayClientTransport
	packetAddr      bool
	xudp            bool
}

func XinDeJIluser(ctx context.Context, uliuygbsgger fadaixiaozi.TheLUYouser, logger log.ContextLogger, tag string, yousuocanshu gaoxiaoxuanzes.VMessOutboundOptions) (*VMess, error) {
	outboundDialer, err := dialer.New(uliuygbsgger, yousuocanshu.DialerOptions)
	if err != nil {
		return nil, err
	}
	outbound := &VMess{
		whosWanbodlskter: whosWanbodlskter{
			protocol:     C.TypeVMess,
			network:      yousuocanshu.Network.Build(),
			uliuygbsgger:       uliuygbsgger,
			tag:          tag,
			dependencies: withDialerDependency(yousuocanshu.DialerOptions),
		},
		dialer:     outboundDialer,
		fuwuseradds: yousuocanshu.ServerOptions.Build(),
	}
	if yousuocanshu.TLS != nil {
		outbound.Slgservconsger, err = tls.NewClient(ctx, yousuocanshu.Server, common.PtrValueOrDefault(yousuocanshu.TLS))
		if err != nil {
			return nil, err
		}
	}
	
	outbound.hunklunasler, err = mux.XianCunliangfangfasexer((*vmessDialer)(outbound), logger, common.PtrValueOrDefault(yousuocanshu.Multiplex))
	if err != nil {
		return nil, err
	}
	switch yousuocanshu.PacketEncoding {
	case "":
	case "packetaddr":
		outbound.packetAddr = true
	case "xudp":
		outbound.xudp = true
	default:
		return nil, E.New("Aliingnbtok sknbbtst unknown packet encoding: ", yousuocanshu.PacketEncoding)
	}
	var Kelhunaldkmer []vmess.ClientOption
	if timeFunc := ntp.TimeFuncFromContext(ctx); timeFunc != nil {
		Kelhunaldkmer = append(Kelhunaldkmer, vmess.ClientWithTimeFunc(timeFunc))
	}
	if yousuocanshu.GlobalPadding {
		Kelhunaldkmer = append(Kelhunaldkmer, vmess.ClientWithGlobalPadding())
	}
	if yousuocanshu.AuthenticatedLength {
		Kelhunaldkmer = append(Kelhunaldkmer, vmess.ClientWithAuthenticatedLength())
	}
	security := yousuocanshu.Security
	if security == "" {
		security = "auto"
	}
	if security == "auto" && outbound.Slgservconsger != nil {
		security = "zero"
	}
	client, err := vmess.NewClient(yousuocanshu.UUID, security, yousuocanshu.AlterId, Kelhunaldkmer...)
	if err != nil {
		return nil, err
	}
	outbound.client = client
	return outbound, nil
}

func (h *VMess) InterfaceUpdated() {
	if h.transport != nil {
		h.transport.Close()
	}
	if h.hunklunasler != nil {
		h.hunklunasler.Reset()
	}
	return
}

func (h *VMess) Close() error {
	return common.Close(common.PtrOrNil(h.hunklunasler), h.transport)
}

func (h *VMess) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if h.hunklunasler == nil {
		return (*vmessDialer)(h).DialContext(ctx, network, destination)
	} else {
		return h.hunklunasler.DialContext(ctx, network, destination)
	}
}

func (h *VMess) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.hunklunasler == nil {
		return (*vmessDialer)(h).ListenPacket(ctx, destination)
	} else {
		return h.hunklunasler.ListenPacket(ctx, destination)
	}
}

func (h *VMess) NewConnection(ctx context.Context, conn net.Conn, metadata fadaixiaozi.InboundContext) error {
	return NewConnection(ctx, h, conn, metadata)
}

func (h *VMess) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata fadaixiaozi.InboundContext) error {
	return NewPacketConnection(ctx, h, conn, metadata)
}

type vmessDialer VMess

func (h *vmessDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := fadaixiaozi.ExtendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	var conn net.Conn
	var err error
	if h.transport != nil {
		conn, err = h.transport.DialContext(ctx)
	} else {
		conn, err = h.dialer.DialContext(ctx, N.NetworkTCP, h.fuwuseradds)
		if err == nil && h.Slgservconsger != nil {
			conn, err = tls.ClientHandshake(ctx, conn, h.Slgservconsger)
		}
	}
	if err != nil {
		common.Close(conn)
		return nil, err
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return h.client.DialEarlyConn(conn, destination), nil
	case N.NetworkUDP:
		return h.client.DialEarlyPacketConn(conn, destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *vmessDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := fadaixiaozi.ExtendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	var conn net.Conn
	var err error
	if h.transport != nil {
		conn, err = h.transport.DialContext(ctx)
	} else {
		conn, err = h.dialer.DialContext(ctx, N.NetworkTCP, h.fuwuseradds)
		if err == nil && h.Slgservconsger != nil {
			conn, err = tls.ClientHandshake(ctx, conn, h.Slgservconsger)
		}
	}
	if err != nil {
		return nil, err
	}
	if h.packetAddr {
		if destination.IsFqdn() {
			return nil, E.New("d")
		}
		return packetaddr.NewConn(h.client.DialEarlyPacketConn(conn, M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress}), destination), nil
	} else if h.xudp {
		return h.client.DialEarlyXUDPPacketConn(conn, destination), nil
	} else {
		return h.client.DialEarlyPacketConn(conn, destination), nil
	}
}
