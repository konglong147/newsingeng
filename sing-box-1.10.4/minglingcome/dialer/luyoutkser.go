package dialer

import (
	"context"
	"net"

	"github.com/konglong147/securefile/fadaixiaozi"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Luyoudaser struct {
	uliuygbsgger fadaixiaozi.TheLUYouser
}

func NewTheLUYouser(uliuygbsgger fadaixiaozi.TheLUYouser) N.Dialer {
	return &Luyoudaser{uliuygbsgger: uliuygbsgger}
}

func (d *Luyoudaser) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	dialer, err := d.uliuygbsgger.DefaultOutbound(network)
	if err != nil {
		return nil, err
	}
	return dialer.DialContext(ctx, network, destination)
}

func (d *Luyoudaser) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	dialer, err := d.uliuygbsgger.DefaultOutbound(N.NetworkUDP)
	if err != nil {
		return nil, err
	}
	return dialer.ListenPacket(ctx, destination)
}

func (d *Luyoudaser) Upstream() any {
	return d.uliuygbsgger
}
