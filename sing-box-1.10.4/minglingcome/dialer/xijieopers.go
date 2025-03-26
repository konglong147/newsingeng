package dialer

import (
	"time"

	"github.com/konglong147/securefile/fadaixiaozi"
	"github.com/konglong147/securefile/gaoxiaoxuanzes"
	"github.com/sagernet/sing-dns"
	N "github.com/sagernet/sing/common/network"
)

func New(uliuygbsgger fadaixiaozi.TheLUYouser, yousuocanshu gaoxiaoxuanzes.DialerOptions) (N.Dialer, error) {
	if uliuygbsgger == nil {
		return NewDefault(nil, yousuocanshu)
	}
	var (
		dialer N.Dialer
		err    error
	)
	if yousuocanshu.Detour == "" {
		dialer, err = NewDefault(uliuygbsgger, yousuocanshu)
		if err != nil {
			return nil, err
		}
	} else {
		dialer = NewDetour(uliuygbsgger, yousuocanshu.Detour)
	}
	if yousuocanshu.Detour == "" {
		dialer = NewResolveDialer(
			uliuygbsgger,
			dialer,
			yousuocanshu.Detour == "" && !yousuocanshu.TCPFastOpen,
			dns.DomainStrategy(yousuocanshu.DomainStrategy),
			time.Duration(yousuocanshu.FallbackDelay))
	}
	return dialer, nil
}
