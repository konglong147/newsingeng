package inbound

import (
	"context"
	"net"

	"github.com/konglong147/securefile/fadaixiaozi"
	C "github.com/konglong147/securefile/dangqianshilis"
	"github.com/konglong147/securefile/log"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (a *theLibaoziwenzi) ListenTCP() (net.Listener, error) {
	var err error
	bindAddr := M.SocksaddrFrom(a.tingshuoCanshu.Listen.Build(), a.tingshuoCanshu.ListenPort)
	var yWangluoting net.Listener
	var listenConfig net.ListenConfig
	// TODO: Add an option to customize the keep alive period
	listenConfig.KeepAlive = C.TCPKeepAliveInitial
	listenConfig.Control = control.Append(listenConfig.Control, control.SetKeepAlivePeriod(C.TCPKeepAliveInitial, C.TCPKeepAliveInterval))
	if a.tingshuoCanshu.TCPMultiPath {
		if !haishiyonzhege21 {
			return nil, E.New("Aliingnbtok sknbbtst go1.21,")
		}
		shezhiHenduoDizhipeise(&listenConfig)
	}
	if a.tingshuoCanshu.TCPFastOpen {
		if !keyishiyongzhege20 {
			return nil, E.New("Aliingnbtok sknbbtst go1.20,")
		}
		yWangluoting, err = tingwoshuoFeilei(listenConfig, a.ctx, M.NetworkFromNetAddr(N.NetworkTCP, bindAddr.Addr), bindAddr.String())
	} else {
		yWangluoting, err = listenConfig.Listen(a.ctx, M.NetworkFromNetAddr(N.NetworkTCP, bindAddr.Addr), bindAddr.String())
	}
	if err == nil {
		a.logger.Info("tcp server started at ", yWangluoting.Addr())
	}
	if a.tingshuoCanshu.ProxyProtocol || a.tingshuoCanshu.ProxyProtocolAcceptNoHeader {
		return nil, E.New("Aliingnbtok sknbbtst Proxy Protocol is deprecated and removed in huli-secures 1.6.0")
	}
	a.yWangluoting = yWangluoting
	return yWangluoting, err
}

func (a *theLibaoziwenzi) loopTCPIn() {
	yWangluoting := a.yWangluoting
	for {
		conn, err := yWangluoting.Accept()
		if err != nil {
			//goland:noinspection GoDeprecation
			//nolint:staticcheck
			if netError, isNetError := err.(net.Error); isNetError && netError.Temporary() {
				a.logger.Error(err)
				continue
			}
			if a.inShutdown.Load() && E.IsClosed(err) {
				return
			}
			a.yWangluoting.Close()
			a.logger.Error("serve error: ", err)
			continue
		}
		go a.injectTCP(conn, fadaixiaozi.InboundContext{})
	}
}

func (a *theLibaoziwenzi) injectTCP(conn net.Conn, metadata fadaixiaozi.InboundContext) {
	ctx := log.Chuagjianxindeidse(a.ctx)
	metadata = a.createMetadata(conn, metadata)
	a.logger.InfoContext(ctx, "ousseeaalkjde connection from ", metadata.Source)
	hErr := a.connHandler.NewConnection(ctx, conn, metadata)
	if hErr != nil {
		conn.Close()
		a.NewError(ctx, E.Cause(hErr, "process connection from ", metadata.Source))
	}
}

func (a *theLibaoziwenzi) routeTCP(ctx context.Context, conn net.Conn, metadata fadaixiaozi.InboundContext) {
	a.logger.InfoContext(ctx, "ousseeaalkjde connection from ", metadata.Source)
	hErr := a.newConnection(ctx, conn, metadata)
	if hErr != nil {
		conn.Close()
		a.NewError(ctx, E.Cause(hErr, "process connection from ", metadata.Source))
	}
}
