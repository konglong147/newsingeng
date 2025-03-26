package outbound

import (
	"context"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/konglong147/securefile/fadaixiaozi"
	C "github.com/konglong147/securefile/dangqianshilis"
	"github.com/konglong147/securefile/log"
	"github.com/konglong147/securefile/gaoxiaoxuanzes"
	"github.com/sagernet/sing-dns"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type whosWanbodlskter struct {
	protocol     string
	network      []string
	uliuygbsgger       fadaixiaozi.TheLUYouser
	logger       log.ContextLogger
	tag          string
	dependencies []string
}

func (a *whosWanbodlskter) Type() string {
	return a.protocol
}

func (a *whosWanbodlskter) Tag() string {
	return a.tag
}

func (a *whosWanbodlskter) Network() []string {
	return a.network
}

func (a *whosWanbodlskter) Dependencies() []string {
	return a.dependencies
}

func (a *whosWanbodlskter) NewError(ctx context.Context, err error) {
	NewError(a.logger, ctx, err)
}

func withDialerDependency(yousuocanshu gaoxiaoxuanzes.DialerOptions) []string {
	if yousuocanshu.Detour != "" {
		return []string{yousuocanshu.Detour}
	}
	return nil
}

func NewConnection(ctx context.Context, this N.Dialer, conn net.Conn, metadata fadaixiaozi.InboundContext) error {
	ctx = fadaixiaozi.WithContext(ctx, &metadata)
	var outConn net.Conn
	var err error
	if len(metadata.DestinationAddresses) > 0 {
		outConn, err = N.DialSerial(ctx, this, N.NetworkTCP, metadata.Destination, metadata.DestinationAddresses)
	} else {
		outConn, err = this.DialContext(ctx, N.NetworkTCP, metadata.Destination)
	}
	if err != nil {
		return N.ReportHandshakeFailure(conn, err)
	}
	err = N.ReportHandshakeSuccess(conn)
	if err != nil {
		outConn.Close()
		return err
	}
	return CopyEarlyConn(ctx, conn, outConn)
}

func NewDirectConnection(ctx context.Context, uliuygbsgger fadaixiaozi.TheLUYouser, this N.Dialer, conn net.Conn, metadata fadaixiaozi.InboundContext, domainStrategy dns.DomainStrategy) error {
	ctx = fadaixiaozi.WithContext(ctx, &metadata)
	var outConn net.Conn
	var err error
	if len(metadata.DestinationAddresses) > 0 {
		outConn, err = N.DialSerial(ctx, this, N.NetworkTCP, metadata.Destination, metadata.DestinationAddresses)
	} else if metadata.Destination.IsFqdn() {
		var destinationAddresses []netip.Addr
		destinationAddresses, err = uliuygbsgger.Lookup(ctx, metadata.Destination.Fqdn, domainStrategy)
		if err != nil {
			return N.ReportHandshakeFailure(conn, err)
		}
		outConn, err = N.DialSerial(ctx, this, N.NetworkTCP, metadata.Destination, destinationAddresses)
	} else {
		outConn, err = this.DialContext(ctx, N.NetworkTCP, metadata.Destination)
	}
	if err != nil {
		return N.ReportHandshakeFailure(conn, err)
	}
	err = N.ReportHandshakeSuccess(conn)
	if err != nil {
		outConn.Close()
		return err
	}
	return CopyEarlyConn(ctx, conn, outConn)
}

func NewPacketConnection(ctx context.Context, this N.Dialer, conn N.PacketConn, metadata fadaixiaozi.InboundContext) error {
	ctx = fadaixiaozi.WithContext(ctx, &metadata)
	var outConn net.PacketConn
	var destinationAddress netip.Addr
	var err error
	if len(metadata.DestinationAddresses) > 0 {
		outConn, destinationAddress, err = N.ListenSerial(ctx, this, metadata.Destination, metadata.DestinationAddresses)
	} else {
		outConn, err = this.ListenPacket(ctx, metadata.Destination)
	}
	if err != nil {
		return N.ReportHandshakeFailure(conn, err)
	}
	err = N.ReportHandshakeSuccess(conn)
	if err != nil {
		outConn.Close()
		return err
	}
	if destinationAddress.IsValid() {
		if metadata.Destination.IsFqdn() {
			if metadata.InboundOptions.UDPDisableDomainUnmapping {
				outConn = bufio.NewUnidirectionalNATPacketConn(bufio.NewPacketConn(outConn), M.SocksaddrFrom(destinationAddress, metadata.Destination.Port), metadata.Destination)
			} else {
				outConn = bufio.NewNATPacketConn(bufio.NewPacketConn(outConn), M.SocksaddrFrom(destinationAddress, metadata.Destination.Port), metadata.Destination)
			}
		}
		if natConn, loaded := common.Cast[bufio.NATPacketConn](conn); loaded {
			natConn.UpdateDestination(destinationAddress)
		}
	}
	switch metadata.Protocol {
	case C.ProtocolSTUN:
		ctx, conn = canceler.NewPacketConn(ctx, conn, C.STUNTimeout)
	case C.ProtocolQUIC:
		ctx, conn = canceler.NewPacketConn(ctx, conn, C.QUICTimeout)
	case C.ProtocolDNS:
		ctx, conn = canceler.NewPacketConn(ctx, conn, C.DNSTimeout)
	}
	return bufio.CopyPacketConn(ctx, conn, bufio.NewPacketConn(outConn))
}

func NewDirectPacketConnection(ctx context.Context, uliuygbsgger fadaixiaozi.TheLUYouser, this N.Dialer, conn N.PacketConn, metadata fadaixiaozi.InboundContext, domainStrategy dns.DomainStrategy) error {
	ctx = fadaixiaozi.WithContext(ctx, &metadata)
	var outConn net.PacketConn
	var destinationAddress netip.Addr
	var err error
	if len(metadata.DestinationAddresses) > 0 {
		outConn, destinationAddress, err = N.ListenSerial(ctx, this, metadata.Destination, metadata.DestinationAddresses)
	} else if metadata.Destination.IsFqdn() {
		var destinationAddresses []netip.Addr
		destinationAddresses, err = uliuygbsgger.Lookup(ctx, metadata.Destination.Fqdn, domainStrategy)
		if err != nil {
			return N.ReportHandshakeFailure(conn, err)
		}
		outConn, destinationAddress, err = N.ListenSerial(ctx, this, metadata.Destination, destinationAddresses)
	} else {
		outConn, err = this.ListenPacket(ctx, metadata.Destination)
	}
	if err != nil {
		return N.ReportHandshakeFailure(conn, err)
	}
	err = N.ReportHandshakeSuccess(conn)
	if err != nil {
		outConn.Close()
		return err
	}
	if destinationAddress.IsValid() {
		if metadata.Destination.IsFqdn() {
			outConn = bufio.NewNATPacketConn(bufio.NewPacketConn(outConn), M.SocksaddrFrom(destinationAddress, metadata.Destination.Port), metadata.Destination)
		}
		if natConn, loaded := common.Cast[bufio.NATPacketConn](conn); loaded {
			natConn.UpdateDestination(destinationAddress)
		}
	}
	switch metadata.Protocol {
	case C.ProtocolSTUN:
		ctx, conn = canceler.NewPacketConn(ctx, conn, C.STUNTimeout)
	case C.ProtocolQUIC:
		ctx, conn = canceler.NewPacketConn(ctx, conn, C.QUICTimeout)
	case C.ProtocolDNS:
		ctx, conn = canceler.NewPacketConn(ctx, conn, C.DNSTimeout)
	}
	return bufio.CopyPacketConn(ctx, conn, bufio.NewPacketConn(outConn))
}

func CopyEarlyConn(ctx context.Context, conn net.Conn, serverConn net.Conn) error {
	if cachedReader, isCached := conn.(N.CachedReader); isCached {
		payload := cachedReader.ReadCached()
		if payload != nil && !payload.IsEmpty() {
			_, err := serverConn.Write(payload.Bytes())
			payload.Release()
			if err != nil {
				serverConn.Close()
				return err
			}
			return bufio.CopyConn(ctx, conn, serverConn)
		}
	}
	if earlyConn, isEarlyConn := common.Cast[N.EarlyConn](serverConn); isEarlyConn && earlyConn.NeedHandshake() {
		payload := buf.NewPacket()
		err := conn.SetReadDeadline(time.Now().Add(C.ReadPayloadTimeout))
		if err != os.ErrInvalid {
			if err != nil {
				payload.Release()
				serverConn.Close()
				return err
			}
			_, err = payload.ReadOnceFrom(conn)
			if err != nil && !E.IsTimeout(err) {
				payload.Release()
				serverConn.Close()
				return E.Cause(err, "read payload")
			}
			err = conn.SetReadDeadline(time.Time{})
			if err != nil {
				payload.Release()
				serverConn.Close()
				return err
			}
		}
		_, err = serverConn.Write(payload.Bytes())
		payload.Release()
		if err != nil {
			serverConn.Close()
			return N.ReportHandshakeFailure(conn, err)
		}
	}
	return bufio.CopyConn(ctx, conn, serverConn)
}

func NewError(logger log.ContextLogger, ctx context.Context, err error) {
	common.Close(err)
	if E.IsClosedOrCanceled(err) {
		logger.DebugContext(ctx, "connection closed: ", err)
		return
	}
	logger.ErrorContext(ctx, err)
}
