package tcputil

import (
	"sync"
)


type TcpGatewayFrontend struct {
	server     *TcpListener
	pack       int
	memPool    MemPool
	links      map[uint32]*tcpGatewayLink
	linksMutex sync.RWMutex
}


type TcpGatewayBackendInfo struct {
	Id             uint32 
	Addr           string 
	TakeClientAddr bool   
}


type TcpGatewayUpdateResult struct {
	Id    uint32 
	IsNew bool   
	Addr  string 
	Error error  
}


func NewTcpGatewayFrontend(addr string, pack int, memPool MemPool, backends []*TcpGatewayBackendInfo) (*TcpGatewayFrontend, error) {
	server, err := Listen(addr, pack, pack+4, memPool)

	if err != nil {
		return nil, err
	}

	var this = &TcpGatewayFrontend{
		server:  server,
		pack:    pack,
		memPool: memPool,
		links:   make(map[uint32]*tcpGatewayLink),
	}

	this.UpdateBackends(backends)

	go func() {
		for {
			var client = this.server.Accpet()

			if client == nil {
				break
			}

			go func() {
				defer func() {
					client.Close()
				}()

				var link, clientId = this.clientInit(client)

				if link == nil || clientId == 0 {
					return
				}

				defer func() {
					link.DelClient(clientId)
					link.SendDelClient(clientId)
				}()

				if link.takeClientAddr {
					var addr = client.conn.RemoteAddr().String()
					var addrMsg = client.NewPackage(4 + 2 + len(addr))

					addrMsg.WriteUint32(clientId).WriteUint8(uint8(len(addr))).WriteBytes([]byte(addr))

					link.SendToBackend(addrMsg.buff)
				}

				for {
					var msg = client.Read()

					if msg == nil {
						break
					}

					setUint(msg, pack, len(msg)-pack)

					setUint32(msg[pack:], clientId)

					link.SendToBackend(msg)
				}
			}()
		}
	}()

	return this, nil
}

func (this *TcpGatewayFrontend) clientInit(client *TcpConn) (link *tcpGatewayLink, clientId uint32) {
	var (
		serverIdMsg []byte
		serverId    uint32
	)

	if serverIdMsg = client.Read(); len(serverIdMsg) != this.pack+4+4 {
		return
	}

	serverId = getUint32(serverIdMsg[this.pack+4:])

	if link = this.getLink(serverId); link == nil {
		return
	}

	if clientId = link.AddClient(client); clientId == 0 {
		return
	}

	return
}

func (this *TcpGatewayFrontend) addLink(id uint32, link *tcpGatewayLink) {
	this.linksMutex.Lock()
	defer this.linksMutex.Unlock()

	this.links[id] = link
}

func (this *TcpGatewayFrontend) delLink(id uint32) {
	this.linksMutex.Lock()
	defer this.linksMutex.Unlock()

	delete(this.links, id)
}

func (this *TcpGatewayFrontend) getLink(id uint32) *tcpGatewayLink {
	this.linksMutex.RLock()
	defer this.linksMutex.RUnlock()

	if link, exists := this.links[id]; exists {
		return link
	}

	return nil
}

func (this *TcpGatewayFrontend) removeOldLinks(backends []*TcpGatewayBackendInfo) []*TcpGatewayUpdateResult {
	this.linksMutex.Lock()
	defer this.linksMutex.Unlock()

	var results = make([]*TcpGatewayUpdateResult, 0, len(backends))

	for id, link := range this.links {
		var needClose = true

		for _, backend := range backends {
			if id == backend.Id && link.addr == backend.Addr {
				needClose = false
				break
			}
		}

		if needClose {
			link.Close(false)
			results = append(results, &TcpGatewayUpdateResult{id, false, link.addr, nil})
		}
	}

	return results
}


func (this *TcpGatewayFrontend) UpdateBackends(backends []*TcpGatewayBackendInfo) []*TcpGatewayUpdateResult {
	var results = this.removeOldLinks(backends)

	for _, backend := range backends {
		if this.getLink(backend.Id) != nil {
			continue
		}

		var link, err = newTcpGatewayLink(this, backend, this.pack, this.memPool)

		if link != nil {
			this.addLink(backend.Id, link)
		}

		results = append(results, &TcpGatewayUpdateResult{backend.Id, true, backend.Addr, err})
	}

	return results
}


func (this *TcpGatewayFrontend) Close() {
	this.linksMutex.Lock()
	defer this.linksMutex.Unlock()

	this.server.Close()

	for _, link := range this.links {
		link.Close(false)
	}
}
