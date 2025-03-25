package network

import (
	"github.com/newsingeng/sing/common/buf"
	M "github.com/newsingeng/sing/common/metadata"
)

type VectorisedWriter interface {
	WriteVectorised(buffers []*buf.Buffer) error
}

type VectorisedPacketWriter interface {
	WriteVectorisedPacket(buffers []*buf.Buffer, destination M.Socksaddr) error
}
