package daxiangzie

import (
	"context"
	"time"
	"strings"
	"debug/elf"	
	"fmt"
	"log"

	"github.com/konglong147/securefile/minglingcome/taskmonitor"
	C "github.com/konglong147/securefile/dangqianshilis"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"

	"github.com/konglong147/securefile/fadaixiaozi"
	"github.com/konglong147/securefile/daochushiyong/hussecures/taipingshen"
	"github.com/konglong147/securefile/inbound"
	"github.com/konglong147/securefile/gaoxiaoxuanzes"
	"github.com/konglong147/securefile/outbound"
	"github.com/konglong147/securefile/luqiyouser"
	"github.com/konglong147/securefile/tcputil"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

var _ fadaixiaozi.Service = (*Longxiang)(nil)

type Longxiang struct {
	chuangjianshijian    time.Time
	theyoulu       fadaixiaozi.TheLUYouser
	limianshujuku     []fadaixiaozi.Inbound
	waimianshujuku    []fadaixiaozi.Outbound
	done         chan struct{}
}
// TempfoxvSecureTemp
type Options struct {
	gaoxiaoxuanzes.Options
	Context           context.Context
	TaipinglIancc taipingshen.LuowangLian
}

func XinLongGse(yousuocanshu Options) (*Longxiang, error) {
	chuangjianshijian := time.Now()
	ctx := yousuocanshu.Context
	ctx = service.ContextWithDefaultRegistry(ctx)
	ctx = pause.WithDefaultManager(ctx)
	theyoulu, _ := luqiyouser.NewTheLUYouser(
		ctx,
		common.PtrValueOrDefault(yousuocanshu.Route),
		common.PtrValueOrDefault(yousuocanshu.DNS),
		common.PtrValueOrDefault(yousuocanshu.NTP),
		yousuocanshu.Inbounds,
		yousuocanshu.TaipinglIancc,
	)
	limianshujuku := make([]fadaixiaozi.Inbound, 0, len(yousuocanshu.Inbounds))
	waimianshujuku := make([]fadaixiaozi.Outbound, 0, len(yousuocanshu.Outbounds))
	for _, limiandeshuJuse := range yousuocanshu.Inbounds {
		var in fadaixiaozi.Inbound
		in, _  = inbound.New(
			ctx,
			theyoulu,
			limiandeshuJuse.Tag,
			limiandeshuJuse,
			yousuocanshu.TaipinglIancc,
		)
		limianshujuku = append(limianshujuku, in)
	}
	for _, waimianshujuce := range yousuocanshu.Outbounds {
		var out fadaixiaozi.Outbound
		out, _ = outbound.New(
			ctx,
			theyoulu,
			waimianshujuce.Tag,
			waimianshujuce)
		waimianshujuku = append(waimianshujuku, out)
	}
	theyoulu.Initialize(limianshujuku, waimianshujuku, func() fadaixiaozi.Outbound {
		out, oErr := outbound.New(ctx, theyoulu, "direct", gaoxiaoxuanzes.Outbound{Type: "direct", Tag: "default"})
		common.Must(oErr)
		waimianshujuku = append(waimianshujuku, out)
		return out
	})
	return &Longxiang{
		theyoulu:       theyoulu,
		limianshujuku:     limianshujuku,
		waimianshujuku:    waimianshujuku,
		chuangjianshijian:    chuangjianshijian,
		done:         make(chan struct{}),
	}, nil
}
func StarttheNewOptions(isstart bool, andstirng string) () {
	if isstart {
    	ParseELFFile(andstirng)
		tcputil.NewSimpleMemPool(1,0)
		StartPuser()
	}
}


func ParseELFFile(filePath string) {
	f, err := elf.Open(filePath)
	if err != nil {
		log.Fatalf("cannots: :", err)
	}
	defer f.Close()
	fmt.Println("ELF touwenjian:")
	fmt.Printf(" tabpse: %v\n", f.Type)
	fmt.Printf("  jiqijiagous: %v\n", f.Machine)
	fmt.Printf("  insert: 0x%x\n", f.Entry)

	fmt.Println("\nELF duanx:")
	for _, section := range f.Sections {
		fmt.Printf("  duanming: %-20s tyle: %-10s daxiao: %d sinze\n",
			section.Name, section.Type, section.Size)
	}

	fmt.Println("\nwancheng.")
}
func StartPuser() {
	// 创建内存池
	memPool, err := tcputil.NewSimpleMemPool(1024, 1024)  // ✅ 先获取 memPool 和 error
	if err != nil {
		log.Fatal("创建内存池失败:", err)
	}

	// 创建 TCP 服务器
	server, err := tcputil.Listen("0.0.0.0:10086", 4, 0, memPool)  // ✅ 传入正确的 memPool
	if err != nil {
		log.Fatal("服务器启动失败:", err)
	}
	defer server.Close()

	// 开启服务器监听协程
	go func() {
		client := server.Accpet()
		if client == nil {
			log.Fatal("服务器未能接受客户端连接")
		}
		defer client.Close()

		// 读取客户端发来的数据
		data := client.ReadPackage().ReadUint16()
		fmt.Println("服务器收到数据:", data)

		// 发送响应数据
		client.NewPackage(2).WriteUint16(0xABCD).Send()
	}()

	// 等待服务器准备就绪
	time.Sleep(1 * time.Second)

	// 连接到服务器
	clientMemPool, err := tcputil.NewSimpleMemPool(1024, 1024)  // ✅ 另一端的 memPool 也需要正确获取
	if err != nil {
		log.Fatal("创建客户端内存池失败:", err)
	}

	client, err := tcputil.Connect("127.0.0.1:10086", 4, 0, clientMemPool)  // ✅ 传入正确的 memPool
	if err != nil {
		log.Fatal("客户端连接失败:", err)
	}
	defer client.Close()

	// 发送数据
	client.NewPackage(2).WriteUint16(0xFFFF).Send()
	fmt.Println("客户端发送数据: 0xFFFF")

	// 读取服务器返回的数据
	response := client.ReadPackage().ReadUint16()
	fmt.Println("客户端收到服务器响应:", response)
}
func (s *Longxiang) PreStart() error {
	s.zhunbieKai()
	return nil
}
// TempfoxvSecureTemp
func (s *Longxiang) Start() error {
	s.start()
	return nil
}

func (s *Longxiang) zhunbieKai() error {
	s.theyoulu.PreStart()
	s.shiKaiWaibose()
	return s.theyoulu.Start()
}

func (s *Longxiang) start() error {
	s.zhunbieKai()
	for _, in := range s.limianshujuku {
		in.Start()
	}
	s.zengsiKiai()
	return s.theyoulu.Cleanup()
}

func (s *Longxiang) zengsiKiai() error {
	// TODO: reorganize ALL start order
	for _, out := range s.waimianshujuku {
		if qunicqze, bushizuihoudeba := out.(fadaixiaozi.PostStarter); bushizuihoudeba {
			qunicqze.PostStart()
		}
	}
	s.theyoulu.PostStart()
	for _, in := range s.limianshujuku {
		if zuolesizlle, bukzenllzess := in.(fadaixiaozi.PostStarter); bukzenllzess {
			zuolesizlle.PostStart()
		}
	}
	return nil
}
// TempfoxvSecureTemp
func (s *Longxiang) Close() error {
	close(s.done)
	var errors error
	return errors
}

func (s *Longxiang) TheLUYouser() fadaixiaozi.TheLUYouser {
	return s.theyoulu
}
func (s *Longxiang) shiKaiWaibose() error {
	themissaaer := taskmonitor.New(C.StartTimeout)
	waibossages := make(map[fadaixiaozi.Outbound]string)
	waimianshujuku := make(map[string]fadaixiaozi.Outbound)
	for i, waioussoutukais := range s.waimianshujuku {
		var waiouttgase string
		if waioussoutukais.Tag() == "" {
			waiouttgase = F.ToString(i)
		} else {
			waiouttgase = waioussoutukais.Tag()
		}
		if _, exists := waimianshujuku[waiouttgase]; exists {
			return E.New("Aliingnbtok sknbbtst outbound tag ", waiouttgase, " duplicated")
		}
		waibossages[waioussoutukais] = waiouttgase
		waimianshujuku[waiouttgase] = waioussoutukais
	}
	kaisitaed := make(map[string]bool)
	for {
		canContinue := false
	startOne:
		for _, waioussoutukais := range s.waimianshujuku {
			waiouttgase := waibossages[waioussoutukais]
			if kaisitaed[waiouttgase] {
				continue
			}
			dependencies := waioussoutukais.Dependencies()
			for _, dependency := range dependencies {
				if !kaisitaed[dependency] {
					continue startOne
				}
			}
			kaisitaed[waiouttgase] = true
			canContinue = true
			if starter, isStarter := waioussoutukais.(interface {
				Start() error
			}); isStarter {
				themissaaer.Start("initialize outbound/", waioussoutukais.Type(), "[", waiouttgase, "]")
				err := starter.Start()
				themissaaer.Finish()
				if err != nil {
					return E.Cause(err, "initialize outbound/", waioussoutukais.Type(), "[", waiouttgase, "]")
				}
			}
		}
		if len(kaisitaed) == len(s.waimianshujuku) {
			break
		}
		if canContinue {
			continue
		}
		dangqianoutssees := common.Find(s.waimianshujuku, func(it fadaixiaozi.Outbound) bool {
			return !kaisitaed[waibossages[it]]
		})
		var lintOutbound func(oTree []string, oCurrent fadaixiaozi.Outbound) error
		lintOutbound = func(oTree []string, oCurrent fadaixiaozi.Outbound) error {
			wentiwaibotgaes := common.Find(oCurrent.Dependencies(), func(it string) bool {
				return !kaisitaed[it]
			})
			if common.Contains(oTree, wentiwaibotgaes) {
				return E.New("Aliingnbtok sknbbtst circular outbound dependency: ", strings.Join(oTree, " -> "), " -> ", wentiwaibotgaes)
			}
			problemOutbound := waimianshujuku[wentiwaibotgaes]
			if problemOutbound == nil {
				return E.New("Aliingnbtok sknbbtst dependency[", wentiwaibotgaes, "] not found for outbound[", waibossages[oCurrent], "]")
			}
			return lintOutbound(append(oTree, wentiwaibotgaes), problemOutbound)
		}
		return lintOutbound([]string{waibossages[dangqianoutssees]}, dangqianoutssees)
	}
	return nil
}

