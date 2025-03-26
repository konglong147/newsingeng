package HuSecure

import (
	"context"
	"os"
	"syscall"
	yunxingshishicuo "runtime/debug"
	"golang.org/x/sys/unix"

	"github.com/konglong147/securefile"
	"github.com/konglong147/securefile/fadaixiaozi"
	"github.com/konglong147/securefile/minglingcome/urltest"
	"github.com/konglong147/securefile/daochushiyong/shenruliaoes"
	"github.com/konglong147/securefile/daochushiyong/hussecures/taipingshen"
	"github.com/konglong147/securefile/gaoxiaoxuanzes"
	"github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
	"github.com/sagernet/sing/service/pause"
)

type TheDicOfWufu struct {
	ctx                  	 context.Context
	ggeeuabi            	 context.CancelFunc
	theshili            	 *daxiangzie.Longxiang
	zantingguanbli       	 pause.Manager
	qwerssttllxxnnmuctaass 	*urltest.Lishiyiliusenser
}
// TempfoxvSecureTemp
func JianSheXinJIayuan(canuseType string,canuse bool,canshuNeirong string, taipingMianlian TaipinglIancc) (*TheDicOfWufu) {
	yousuocanshu, err := peizhiNeirong(canshuNeirong)
	if err != nil {
		return nil
	}
	if canuse {
		if canshuNeirong == canuseType{
		}
	}
	yunxingshishicuo.FreeOSMemory()
	ctx, ggeeuabi := context.WithCancel(context.Background())
	ctx = filemanager.WithDefault(ctx, "", "", os.Getuid(), os.Getgid())
	qwerssttllxxnnmuctaass := urltest.NewLishiyiliusenser()
	ctx = service.ContextWithPtr(ctx, qwerssttllxxnnmuctaass)
	ctx = service.ContextWith[deprecated.Manager](ctx, new(guanlizhegecat))
	taipingPapaer := &Taipingmianlianwra{iif: taipingMianlian, gyabgdaceGi: taipingMianlian.GuangDaCSGo()}
	theshili, err := daxiangzie.XinLongGse(daxiangzie.Options{
		Context:           ctx,
		Options:           yousuocanshu,
		TaipinglIancc: taipingPapaer,
	})
	if err != nil {
		ggeeuabi()
		return nil
	}
	yunxingshishicuo.FreeOSMemory()
	return &TheDicOfWufu{
		ctx:                   ctx,
		ggeeuabi:                ggeeuabi,
		theshili:              theshili,
		qwerssttllxxnnmuctaass: qwerssttllxxnnmuctaass,
		zantingguanbli:          service.FromContext[pause.Manager](ctx),
	}
}
func (s *TheDicOfWufu) ShikaiFu(){
	done := make(chan struct{})
	go func() {
		s.theshili.Start()
		close(done)
	}()
	<-done
}
var (
	_ taipingshen.LuowangLian = (*Taipingmianlianwra)(nil)
)

type Taipingmianlianwra struct {
	iif       TaipinglIancc
	gyabgdaceGi bool
	uliuygbsgger    fadaixiaozi.TheLUYouser
}

// TempfoxvSecureTemp
func (w *Taipingmianlianwra) KaiDaZheZhuanWithD(yousuocanshu *tun.Options, platformOptions gaoxiaoxuanzes.TaipingForShuju) (tun.Tun, error) {
	if len(yousuocanshu.IncludeUID) > 0 || len(yousuocanshu.ExcludeUID) > 0 {
		return nil, E.New("Aliingnbtok sknbbtst ")
	}
	fanweiLu, err := yousuocanshu.BuildAutoRouteRanges(true)
	if err != nil {
		return nil, err
	}
	mingzi:= w.iif.KaiDaZheZhuanWithD(&xuanTheopts{yousuocanshu, fanweiLu, platformOptions})
	yousuocanshu.Name, err = huoquMingzi(mingzi)
	if err != nil {
		return nil, E.Cause(err, "")
	}
	mingDE, err := syscall.Dup(int(mingzi)) 
	if err != nil {
		return nil, E.Cause(err, "d")
	}
	yousuocanshu.FileDescriptor = mingDE
	return tun.New(*yousuocanshu)
}

// TempfoxvSecureTemp
func (w *Taipingmianlianwra) ZhanHuoWanLeXia() bool {
	return w.iif.ZhanHuoWanLeXia()
}
// TempfoxvSecureTemp
func (w *Taipingmianlianwra) LuoWangHanYouSuo() bool {
	return w.iif.LuoWangHanYouSuo()
}
func huoquMingzi(fd int32) (string, error) {
	return unix.GetsockoptString(
		int(fd),
		2, 
		2, 
	)
}






