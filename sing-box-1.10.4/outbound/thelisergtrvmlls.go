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
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ fadaixiaozi.Outbound = (*VLESS)(nil)

type VLESS struct {
	whosWanbodlskter
	dialer          N.Dialer
	client          *vless.Client
	fuwuseradds      M.Socksaddr
	hunklunasler *mux.Client
	Slgservconsger       tls.Config
	transport       fadaixiaozi.V2RayClientTransport
	packetAddr      bool
	xudp            bool
}

func Xinbjskgsseebb(ctx context.Context, uliuygbsgger fadaixiaozi.TheLUYouser, logger log.ContextLogger, tag string, yousuocanshu gaoxiaoxuanzes.VLESSOutboundOptions) (*VLESS, error) {
	outboundDialer, err := dialer.New(uliuygbsgger, yousuocanshu.DialerOptions)
	if err != nil {
		return nil, err
	}
	outbound := &VLESS{
		whosWanbodlskter: whosWanbodlskter{
			protocol:     C.TypeVLESS,
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
	if yousuocanshu.PacketEncoding == nil {
		outbound.xudp = true
	} else {
		switch *yousuocanshu.PacketEncoding {
		case "":
		case "packetaddr":
			outbound.packetAddr = true
		case "xudp":
			outbound.xudp = true
		default:
			return nil, E.New("Aliingnbtok sknbbtst unknown packet encoding: ", yousuocanshu.PacketEncoding)
		}
	}
	outbound.client, err = vless.NewClient(yousuocanshu.UUID, yousuocanshu.Flow, logger)
	if err != nil {
		return nil, err
	}
	outbound.hunklunasler, err = mux.XianCunliangfangfasexer((*vlessDialer)(outbound), logger, common.PtrValueOrDefault(yousuocanshu.Multiplex))
	if err != nil {
		return nil, err
	}
	return outbound, nil
}

func (h *VLESS) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if h.hunklunasler == nil {
		return (*vlessDialer)(h).DialContext(ctx, network, destination)
	} else {
		return h.hunklunasler.DialContext(ctx, network, destination)
	}
}

func (h *VLESS) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.hunklunasler == nil {
		return (*vlessDialer)(h).ListenPacket(ctx, destination)
	} else {
		return h.hunklunasler.ListenPacket(ctx, destination)
	}
}

func (h *VLESS) NewConnection(ctx context.Context, conn net.Conn, metadata fadaixiaozi.InboundContext) error {
	return NewConnection(ctx, h, conn, metadata)
}

func (h *VLESS) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata fadaixiaozi.InboundContext) error {
	return NewPacketConnection(ctx, h, conn, metadata)
}

func (h *VLESS) InterfaceUpdated() {
	if h.transport != nil {
		h.transport.Close()
	}
	if h.hunklunasler != nil {
		h.hunklunasler.Reset()
	}
	return
}

func (h *VLESS) Close() error {
	return common.Close(common.PtrOrNil(h.hunklunasler), h.transport)
}

type vlessDialer VLESS

func (h *vlessDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
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
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return h.client.DialEarlyConn(conn, destination)
	case N.NetworkUDP:
		if h.xudp {
			return h.client.DialEarlyXUDPPacketConn(conn, destination)
		} else if h.packetAddr {
			if destination.IsFqdn() {
				return nil, E.New("Aliingnbtok sknbbtst packetaddr: domain destination is not supported")
			}
			packetConn, err := h.client.DialEarlyPacketConn(conn, M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress})
			if err != nil {
				return nil, err
			}
			return bufio.NewBindPacketConn(packetaddr.NewConn(packetConn, destination), destination), nil
		} else {
			return h.client.DialEarlyPacketConn(conn, destination)
		}
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *vlessDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
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
	if h.xudp {
		return h.client.DialEarlyXUDPPacketConn(conn, destination)
	} else if h.packetAddr {
		if destination.IsFqdn() {
			return nil, E.New("Aliingnbtok sknbbtst packetaddr: domain destination is not supported")
		}
		conn, err := h.client.DialEarlyPacketConn(conn, M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress})
		if err != nil {
			return nil, err
		}
		return packetaddr.NewConn(conn, destination), nil
	} else {
		return h.client.DialEarlyPacketConn(conn, destination)
	}
}
