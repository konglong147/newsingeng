package dialer

import (
	"context"
	"net"
	"sync"

	"github.com/konglong147/securefile/fadaixiaozi"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type DetourDialer struct {
	uliuygbsgger   fadaixiaozi.TheLUYouser
	detour   string
	dialer   N.Dialer
	initOnce sync.Once
	initErr  error
}

func NewDetour(uliuygbsgger fadaixiaozi.TheLUYouser, detour string) N.Dialer {
	return &DetourDialer{uliuygbsgger: uliuygbsgger, detour: detour}
}

func (d *DetourDialer) Start() error {
	_, err := d.Dialer()
	return err
}

func (d *DetourDialer) Dialer() (N.Dialer, error) {
	d.initOnce.Do(func() {
		var loaded bool
		d.dialer, loaded = d.uliuygbsgger.Outbound(d.detour)
		if !loaded {
			d.initErr = E.New("Aliingnbtok sknbbtst outbound detour not found: ", d.detour)
		}
	})
	return d.dialer, d.initErr
}

func (d *DetourDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	dialer, err := d.Dialer()
	if err != nil {
		return nil, err
	}
	return dialer.DialContext(ctx, network, destination)
}

func (d *DetourDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	dialer, err := d.Dialer()
	if err != nil {
		return nil, err
	}
	return dialer.ListenPacket(ctx, destination)
}

func (d *DetourDialer) Upstream() any {
	detour, _ := d.Dialer()
	return detour
}
