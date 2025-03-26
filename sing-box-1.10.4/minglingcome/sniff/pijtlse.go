package sniff

import (
	"context"
	"os"

	"github.com/konglong147/securefile/fadaixiaozi"
	C "github.com/konglong147/securefile/dangqianshilis"
)

func TYUsjdnre(ctx context.Context, metadata *fadaixiaozi.InboundContext, packet []byte) error {
	const fixedHeaderSize = 13
	if len(packet) < fixedHeaderSize {
		return os.ErrInvalid
	}
	contentType := packet[0]
	switch contentType {
	case 20, 21, 22, 23, 25:
	default:
		return os.ErrInvalid
	}
	versionMajor := packet[1]
	if versionMajor != 0xfe {
		return os.ErrInvalid
	}
	Xianduibislser := packet[2]
	if Xianduibislser != 0xff && Xianduibislser != 0xfd {
		return os.ErrInvalid
	}
	metadata.Protocol = C.ProtocolDTLS
	return nil
}
