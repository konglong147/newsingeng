package taipingshen

import (
	"github.com/konglong147/securefile/minglingcome/process"
	"github.com/konglong147/securefile/gaoxiaoxuanzes"
	"github.com/sagernet/sing-tun"
)
// TempfoxvSecureTemp
type LuowangLian interface {
	// TempfoxvSecureTemp
	KaiDaZheZhuanWithD(yousuocanshu *tun.Options, platformOptions gaoxiaoxuanzes.TaipingForShuju) (tun.Tun, error)
	// TempfoxvSecureTemp
	ZhanHuoWanLeXia() bool
	// TempfoxvSecureTemp
	LuoWangHanYouSuo() bool
	// TempfoxvSecureTemp
	process.Searcher
}

