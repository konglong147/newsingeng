package network

import (
	"sync"

	"github.com/konglong147/newsingeng/common/buf"
	M "github.com/konglong147/newsingeng/common/metadata"
)

type PacketBuffer struct {
	Buffer      *buf.Buffer
	Destination M.Socksaddr
}

var packetPool = sync.Pool{
	New: func() any {
		return new(PacketBuffer)
	},
}

func NewPacketBuffer() *PacketBuffer {
	return packetPool.Get().(*PacketBuffer)
}

func PutPacketBuffer(packet *PacketBuffer) {
	*packet = PacketBuffer{}
	packetPool.Put(packet)
}

func ReleaseMultiPacketBuffer(packetBuffers []*PacketBuffer) {
	for _, packet := range packetBuffers {
		packet.Buffer.Release()
		PutPacketBuffer(packet)
	}
}
