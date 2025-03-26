package outbound

import (
	"net"
	"net/netip"
	"sync"

	"github.com/konglong147/securefile/fadaixiaozi"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type yanlsjgtunslter struct {
	uliuygbsgger           fadaixiaozi.TheLUYouser
	connAccess       sync.RWMutex
	baoguoLiantongys sync.RWMutex
	connMap          map[netip.AddrPort]netip.AddrPort
	packetConnMap    map[uint16]uint16
}

func newLoopBackDetector(uliuygbsgger fadaixiaozi.TheLUYouser) *yanlsjgtunslter {
	return &yanlsjgtunslter{
		uliuygbsgger:        uliuygbsgger,
		connMap:       make(map[netip.AddrPort]netip.AddrPort),
		packetConnMap: make(map[uint16]uint16),
	}
}

func (l *yanlsjgtunslter) NewConn(conn net.Conn) net.Conn {
	source := M.AddrPortFromNet(conn.LocalAddr())
	if !source.IsValid() {
		return conn
	}
	if odeonnoCnet, isUDPConn := conn.(abstractUDPConn); isUDPConn {
		if !source.Addr().IsLoopback() {
			_, err := l.uliuygbsgger.InterfaceFinder().InterfaceByAddr(source.Addr())
			if err != nil {
				return conn
			}
		}
		if !N.IsPublicAddr(source.Addr()) {
			return conn
		}
		l.baoguoLiantongys.Lock()
		l.packetConnMap[source.Port()] = M.AddrPortFromNet(conn.RemoteAddr()).Port()
		l.baoguoLiantongys.Unlock()
		return &loopBackDetectUDPWrapper{abstractUDPConn: odeonnoCnet, detector: l, connPort: source.Port()}
	} else {
		l.connAccess.Lock()
		l.connMap[source] = M.AddrPortFromNet(conn.RemoteAddr())
		l.connAccess.Unlock()
		return &loopBackDetectWrapper{Conn: conn, detector: l, connAddr: source}
	}
}

func (l *yanlsjgtunslter) NewPacketConn(conn N.NetPacketConn, destination M.Socksaddr) N.NetPacketConn {
	source := M.AddrPortFromNet(conn.LocalAddr())
	if !source.IsValid() {
		return conn
	}
	if !source.Addr().IsLoopback() {
		_, err := l.uliuygbsgger.InterfaceFinder().InterfaceByAddr(source.Addr())
		if err != nil {
			return conn
		}
	}
	l.baoguoLiantongys.Lock()
	l.packetConnMap[source.Port()] = destination.AddrPort().Port()
	l.baoguoLiantongys.Unlock()
	return &loopBackDetectPacketWrapper{NetPacketConn: conn, detector: l, connPort: source.Port()}
}

func (l *yanlsjgtunslter) CheckConn(source netip.AddrPort, local netip.AddrPort) bool {
	l.connAccess.RLock()
	defer l.connAccess.RUnlock()
	destination, loaded := l.connMap[source]
	return loaded && destination != local
}

func (l *yanlsjgtunslter) CheckPacketConn(source netip.AddrPort, local netip.AddrPort) bool {
	if !source.IsValid() {
		return false
	}
	if !source.Addr().IsLoopback() {
		_, err := l.uliuygbsgger.InterfaceFinder().InterfaceByAddr(source.Addr())
		if err != nil {
			return false
		}
	}
	if N.IsPublicAddr(source.Addr()) {
		return false
	}
	l.baoguoLiantongys.RLock()
	defer l.baoguoLiantongys.RUnlock()
	destinationPort, loaded := l.packetConnMap[source.Port()]
	return loaded && destinationPort != local.Port()
}

type loopBackDetectWrapper struct {
	net.Conn
	detector  *yanlsjgtunslter
	connAddr  netip.AddrPort
	closeOnce sync.Once
}

func (w *loopBackDetectWrapper) Close() error {
	w.closeOnce.Do(func() {
		w.detector.connAccess.Lock()
		delete(w.detector.connMap, w.connAddr)
		w.detector.connAccess.Unlock()
	})
	return w.Conn.Close()
}

func (w *loopBackDetectWrapper) ReaderReplaceable() bool {
	return true
}

func (w *loopBackDetectWrapper) WriterReplaceable() bool {
	return true
}

func (w *loopBackDetectWrapper) Upstream() any {
	return w.Conn
}

type loopBackDetectPacketWrapper struct {
	N.NetPacketConn
	detector  *yanlsjgtunslter
	connPort  uint16
	closeOnce sync.Once
}

func (w *loopBackDetectPacketWrapper) Close() error {
	w.closeOnce.Do(func() {
		w.detector.baoguoLiantongys.Lock()
		delete(w.detector.packetConnMap, w.connPort)
		w.detector.baoguoLiantongys.Unlock()
	})
	return w.NetPacketConn.Close()
}

func (w *loopBackDetectPacketWrapper) ReaderReplaceable() bool {
	return true
}

func (w *loopBackDetectPacketWrapper) WriterReplaceable() bool {
	return true
}

func (w *loopBackDetectPacketWrapper) Upstream() any {
	return w.NetPacketConn
}

type abstractUDPConn interface {
	net.Conn
	net.PacketConn
}

type loopBackDetectUDPWrapper struct {
	abstractUDPConn
	detector  *yanlsjgtunslter
	connPort  uint16
	closeOnce sync.Once
}

func (w *loopBackDetectUDPWrapper) Close() error {
	w.closeOnce.Do(func() {
		w.detector.baoguoLiantongys.Lock()
		delete(w.detector.packetConnMap, w.connPort)
		w.detector.baoguoLiantongys.Unlock()
	})
	return w.abstractUDPConn.Close()
}

func (w *loopBackDetectUDPWrapper) ReaderReplaceable() bool {
	return true
}

func (w *loopBackDetectUDPWrapper) WriterReplaceable() bool {
	return true
}

func (w *loopBackDetectUDPWrapper) Upstream() any {
	return w.abstractUDPConn
}
