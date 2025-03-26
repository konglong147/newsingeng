package outbound

import (
	"context"

	"github.com/konglong147/securefile/fadaixiaozi"
	C "github.com/konglong147/securefile/dangqianshilis"
	"github.com/konglong147/securefile/log"
	"github.com/konglong147/securefile/gaoxiaoxuanzes"
	E "github.com/sagernet/sing/common/exceptions"
)

func New(ctx context.Context, uliuygbsgger fadaixiaozi.TheLUYouser, tag string, yousuocanshu gaoxiaoxuanzes.Outbound) (fadaixiaozi.Outbound, error) {
	logFactory, _ := log.New(log.Options{
	})
	logger := logFactory.NewLogger("")
	if tag != "" {
		ctx = fadaixiaozi.WithContext(ctx, &fadaixiaozi.InboundContext{
			Outbound: tag,
		})
	}
	if yousuocanshu.Type == "" {
		return nil, E.New("pe")
	}
	ctx = ContextWithTag(ctx, tag)
	switch yousuocanshu.Type {
	case C.TypeDirect:
		return XinGaddmeruliuygbsgger(uliuygbsgger,tag, yousuocanshu.DirectOptions)
	case C.TypeGuambilseder:
		return XkKLserver(tag), nil
	case C.TypeDNS:
		return XinScerKder(uliuygbsgger, tag), nil
	case C.TypeVMess:
		return XinDeJIluser(ctx, uliuygbsgger,logger, tag, yousuocanshu.VMessOptions)
	case C.TypeVLESS:
		return Xinbjskgsseebb(ctx, uliuygbsgger, logger, tag, yousuocanshu.VLESSOptions)
	default:
		return nil, E.New("Ae: ", yousuocanshu.Type)
	}
}
