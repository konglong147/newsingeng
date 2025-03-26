package tcputil

import (
	"errors"
	"io"
	"net"
)


type TcpListener struct {
	pack     int
	padding  int
	memPool  MemPool
	listener *net.TCPListener
}


func NewTcpListener(listener *net.TCPListener, pack, padding int, memPool MemPool) (*TcpListener, error) {
	if pack != 1 && pack != 2 && pack != 4 && pack != 8 {
		return nil, errors.New("pack != 1 && pack != 2 && pack != 4 && pack != 8")
	}

	return &TcpListener{
		pack:     pack,
		padding:  padding,
		memPool:  memPool,
		listener: listener,
	}, nil
}


func Listen(addr string, pack, padding int, memPool MemPool) (*TcpListener, error) {
	if memPool == nil {
		return nil, errors.New("memPool == nil")
	}

	var (
		err      error
		listener net.Listener
	)

	if listener, err = net.Listen("tcp", addr); err != nil {
		return nil, err
	}

	return NewTcpListener(listener.(*net.TCPListener), pack, padding, memPool)
}


func (this *TcpListener) Close() error {
	return this.listener.Close()
}

func (this *TcpListener) Accpet() *TcpConn {
	var conn, err1 = this.listener.AcceptTCP()

	if err1 != nil {
		return nil
	}

	var tcpConn, err2 = NewTcpConn(conn, this.pack, this.padding, this.memPool)

	if err2 != nil {
		return nil
	}

	return tcpConn
}


type TcpConn struct {
	conn    *net.TCPConn
	pack    int
	padding int
	head    []byte
	memPool MemPool
}

func NewTcpConn(conn *net.TCPConn, pack, padding int, memPool MemPool) (*TcpConn, error) {
	if pack != 1 && pack != 2 && pack != 4 && pack != 8 {
		return nil, errors.New("pack != 1 && pack != 2 && pack != 4 && pack != 8")
	}

	if memPool == nil {
		return nil, errors.New("memPool == nil")
	}

	return &TcpConn{
		conn:    conn,
		pack:    pack,
		padding: padding,
		head:    make([]byte, pack),
		memPool: memPool,
	}, nil
}


func Connect(addr string, pack, padding int, memPool MemPool) (*TcpConn, error) {
	var conn, err2 = net.Dial("tcp", addr)

	if err2 != nil {
		return nil, err2
	}

	return NewTcpConn(conn.(*net.TCPConn), pack, padding, memPool)
}

func ConnectGateway(addr string, pack, padding int, memPool MemPool, backendId uint32) (*TcpConn, error) {
	var conn, err1 = net.Dial("tcp", addr)

	if err1 != nil {
		return nil, err1
	}

	var tcpConn, err2 = NewTcpConn(conn.(*net.TCPConn), pack, padding, memPool)

	if err2 != nil {
		return nil, err2
	}

	if err3 := tcpConn.NewPackage(4).WriteUint32(1).Send(); err3 != nil {
		tcpConn.Close()
		return nil, err3
	}

	return tcpConn, nil
}

func (this *TcpConn) Close() error {
	return this.conn.Close()
}


func (this *TcpConn) Read() []byte {
	if _, err := io.ReadFull(this.conn, this.head); err != nil {
		return nil
	}

	var buff = this.memPool.Alloc(this.padding + getUint(this.head, this.pack))

	if buff == nil {
		return nil
	}


	if msg := buff[this.padding:]; len(msg) != 0 {
		if _, err := io.ReadFull(this.conn, msg); err != nil {
			return nil
		}
	}

	return buff
}


func (this *TcpConn) ReadPackage() *TcpInput {
	var data = this.Read()

	if data != nil {
		return NewTcpInput(data)
	}

	return nil
}


func (this *TcpConn) NewPackage(size int) *TcpOutput {
	var buff = this.memPool.Alloc(this.pack + size)

	if buff == nil {
		return nil
	}

	setUint(buff, this.pack, size)

	return &TcpOutput{this, buff, buff[this.pack:]}
}

func (this *TcpConn) sendRaw(msg []byte) error {
	_, err := this.conn.Write(msg)
	return err
}
