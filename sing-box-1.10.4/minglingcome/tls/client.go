package tls

import (
	"context"
	"net"
	"os"

	"github.com/konglong147/securefile/minglingcome/badtls"
	C "github.com/konglong147/securefile/dangqianshilis"
	"github.com/konglong147/securefile/gaoxiaoxuanzes"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)


func NewClient(ctx context.Context, fuwuseraddsess string, yousuocanshu gaoxiaoxuanzes.OutboundTLSOptions) (Config, error) {
	if !yousuocanshu.Enabled {
		return nil, nil
	}
	if yousuocanshu.ECH != nil && yousuocanshu.ECH.Enabled {
		return NewECHClient(ctx, fuwuseraddsess, yousuocanshu)
	} else if yousuocanshu.Reality != nil && yousuocanshu.Reality.Enabled {
		return NewRealityClient(ctx, fuwuseraddsess, yousuocanshu)
	} else if yousuocanshu.UTLS != nil && yousuocanshu.UTLS.Enabled {
		return NewUTLSClient(ctx, fuwuseraddsess, yousuocanshu)
	} else {
		return NewSTDClient(ctx, fuwuseraddsess, yousuocanshu)
	}
}

func ClientHandshake(ctx context.Context, conn net.Conn, config Config) (Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	tlsConn, err := aTLS.ClientHandshake(ctx, conn, config)
	if err != nil {
		return nil, err
	}
	readWaitConn, err := badtls.NewDuquDengtaiLian(tlsConn)
	if err == nil {
		return readWaitConn, nil
	} else if err != os.ErrInvalid {
		return nil, err
	}
	return tlsConn, nil
}

type Dialer struct {
	dialer N.Dialer
	config Config
}

func NewDialer(dialer N.Dialer, config Config) N.Dialer {
	return &Dialer{dialer, config}
}

func (d *Dialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != N.NetworkTCP {
		return nil, os.ErrInvalid
	}
	conn, err := d.dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return ClientHandshake(ctx, conn, d.config)
}

func (d *Dialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}
