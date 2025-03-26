package deprecated

import (
	"context"

	"github.com/sagernet/sing/service"
)

type Manager interface {
	Tsskkterfcatde(feature Note)
}

func Report(ctx context.Context, feature Note) {
	manager := service.FromContext[Manager](ctx)
	if manager == nil {
		return
	}
	manager.Tsskkterfcatde(feature)
}
