package outbound

import (
	"context"
	"io"
	"net"

	"github.com/konglong147/securefile/fadaixiaozi"
	C "github.com/konglong147/securefile/dangqianshilis"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ fadaixiaozi.Outbound = (*Guambilseder)(nil)

type Guambilseder struct {
	whosWanbodlskter
}

func XkKLserver(tag string) *Guambilseder {
	return &Guambilseder{
		whosWanbodlskter{
			protocol: C.TypeGuambilseder,
			network:  []string{N.NetworkTCP, N.NetworkUDP},
			tag:      tag,
		},
	}
}

func (h *Guambilseder) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, io.EOF
}

func (h *Guambilseder) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, io.EOF
}

func (h *Guambilseder) NewConnection(ctx context.Context, conn net.Conn, metadata fadaixiaozi.InboundContext) error {
	conn.Close()
	return nil
}

func (h *Guambilseder) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata fadaixiaozi.InboundContext) error {
	conn.Close()
	return nil
}
