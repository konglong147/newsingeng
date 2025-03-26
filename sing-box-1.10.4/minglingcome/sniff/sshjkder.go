package sniff

import (
	"bufio"
	"context"
	"io"
	"os"
	"strings"

	"github.com/konglong147/securefile/fadaixiaozi"
	C "github.com/konglong147/securefile/dangqianshilis"
)

func SSH(_ context.Context, metadata *fadaixiaozi.InboundContext, reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	if !scanner.Scan() {
		return os.ErrInvalid
	}
	fistLine := scanner.Text()
	if !strings.HasPrefix(fistLine, "SSH-2.0-") {
		return os.ErrInvalid
	}
	metadata.Protocol = C.ProtocolSSH
	metadata.Client = fistLine[8:]
	return nil
}
