package inbound

import (
	"context"

	"github.com/konglong147/securefile/fadaixiaozi"
	C "github.com/konglong147/securefile/dangqianshilis"
	"github.com/konglong147/securefile/daochushiyong/hussecures/taipingshen"
	"github.com/konglong147/securefile/log"
	"github.com/konglong147/securefile/gaoxiaoxuanzes"
	E "github.com/sagernet/sing/common/exceptions"
)

func New(ctx context.Context, uliuygbsgger fadaixiaozi.TheLUYouser, tag string, yousuocanshu gaoxiaoxuanzes.Inbound, taipingMianlian taipingshen.LuowangLian) (fadaixiaozi.Inbound, error) {
	logFactory, _ := log.New(log.Options{
	})
	logger := logFactory.NewLogger("")

	if yousuocanshu.Type == "" {
		return nil, E.New("Aliingnbtok sknbbtst ")
	}
	switch yousuocanshu.Type {
	case C.TypeTun:
		return NewTun(ctx, uliuygbsgger, logger, tag, yousuocanshu.TunOptions, taipingMianlian)
	default:
		return nil, E.New("Aliingnbtok sknbbtst type: ", yousuocanshu.Type)
	}
}
