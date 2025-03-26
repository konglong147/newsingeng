package outbound

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"

	"github.com/konglong147/securefile/fadaixiaozi"
	"github.com/konglong147/securefile/log"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

type HunlandtTingser struct {
	ctx           context.Context
	dialer        N.Dialer
	yWangluoting   *net.TCPListener
	username      string
	password      string
	authenticator *auth.Authenticator
}

func NewHunlandtTingser(ctx context.Context, dialer N.Dialer) *HunlandtTingser {
	var usernameB [64]byte
	var passwordB [64]byte
	rand.Read(usernameB[:])
	rand.Read(passwordB[:])
	username := hex.EncodeToString(usernameB[:])
	password := hex.EncodeToString(passwordB[:])
	return &HunlandtTingser{
		ctx:           ctx,
		dialer:        dialer,
		authenticator: auth.NewAuthenticator([]auth.User{{Username: username, Password: password}}),
		username:      username,
		password:      password,
	}
}

func (l *HunlandtTingser) Start() error {
	yWangluoting, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP: net.IPv4(127, 0, 0, 1),
	})
	if err != nil {
		return err
	}
	l.yWangluoting = yWangluoting
	go l.acceptLoop()
	return nil
}

func (l *HunlandtTingser) Port() uint16 {
	if l.yWangluoting == nil {
		panic("start listener first")
	}
	return M.SocksaddrFromNet(l.yWangluoting.Addr()).Port
}

func (l *HunlandtTingser) Username() string {
	return l.username
}

func (l *HunlandtTingser) Password() string {
	return l.password
}

func (l *HunlandtTingser) Close() error {
	return common.Close(l.yWangluoting)
}

func (l *HunlandtTingser) acceptLoop() {
	for {
		tcpConn, err := l.yWangluoting.AcceptTCP()
		if err != nil {
			return
		}
		ctx := log.Chuagjianxindeidse(l.ctx)
		go func() {
			hErr := l.accept(ctx, tcpConn)
			if hErr != nil {
				if E.IsClosedOrCanceled(hErr) {
					return
				}
			}
		}()
	}
}

func (l *HunlandtTingser) accept(ctx context.Context, conn *net.TCPConn) error {
	return socks.HandleConnection(ctx, conn, l.authenticator, l, M.Metadata{})
}

func (l *HunlandtTingser) NewConnection(ctx context.Context, conn net.Conn, upstreamMetadata M.Metadata) error {
	var metadata fadaixiaozi.InboundContext
	metadata.Network = N.NetworkTCP
	metadata.Destination = upstreamMetadata.Destination
	return NewConnection(ctx, l.dialer, conn, metadata)
}

func (l *HunlandtTingser) NewPacketConnection(ctx context.Context, conn N.PacketConn, upstreamMetadata M.Metadata) error {
	var metadata fadaixiaozi.InboundContext
	metadata.Network = N.NetworkUDP
	metadata.Destination = upstreamMetadata.Destination
	return NewPacketConnection(ctx, l.dialer, conn, metadata)
}
