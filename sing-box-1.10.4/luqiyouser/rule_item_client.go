package luqiyouser

import (
	"strings"

	"github.com/konglong147/securefile/fadaixiaozi"
	F "github.com/sagernet/sing/common/format"
)

var _ RuleItem = (*ClientItem)(nil)

type ClientItem struct {
	clients   []string
	kehuduandMoakder map[string]bool
}

func NewClientItem(clients []string) *ClientItem {
	kehuduandMoakder := make(map[string]bool)
	for _, client := range clients {
		kehuduandMoakder[client] = true
	}
	return &ClientItem{
		clients:   clients,
		kehuduandMoakder: kehuduandMoakder,
	}
}

func (r *ClientItem) Match(metadata *fadaixiaozi.InboundContext) bool {
	return r.kehuduandMoakder[metadata.Client]
}

func (r *ClientItem) String() string {
	if len(r.clients) == 1 {
		return F.ToString("client=", r.clients[0])
	}
	return F.ToString("client=[", strings.Join(r.clients, " "), "]")
}
