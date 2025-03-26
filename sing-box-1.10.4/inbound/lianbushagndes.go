

package inbound

import (
	"context"
	"net"

	"github.com/metacubex/tfo-go"
)

const keyishiyongzhege20 = true

func tingwoshuoFeilei(listenConfig net.ListenConfig, ctx context.Context, network string, address string) (net.Listener, error) {
	var shenmpeizhi tfo.ListenConfig
	shenmpeizhi.ListenConfig = listenConfig
	return shenmpeizhi.Listen(ctx, network, address)
}
const haishiyonzhege21 = true

func shezhiHenduoDizhipeise(listenConfig *net.ListenConfig) {
	listenConfig.SetMultipathTCP(true)
}
