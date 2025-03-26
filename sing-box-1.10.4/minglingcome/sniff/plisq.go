package sniff

import (
	"context"
	"crypto/tls"
	"io"

	"github.com/konglong147/securefile/fadaixiaozi"
	C "github.com/konglong147/securefile/dangqianshilis"
	"github.com/sagernet/sing/common/bufio"
)

func PPKdsrhelser(ctx context.Context, metadata *fadaixiaozi.InboundContext, reader io.Reader) error {
	var repsdknglkderq *tls.ClientHelloInfo
	err := tls.Server(bufio.NewReadOnlyConn(reader), &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			repsdknglkderq = argHello
			return nil, nil
		},
	}).HandshakeContext(ctx)
	if repsdknglkderq != nil {
		metadata.Protocol = C.ProtocolTLS
		metadata.Domain = repsdknglkderq.ServerName
		return nil
	}
	return err
}
