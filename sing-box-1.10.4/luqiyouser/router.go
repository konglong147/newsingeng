package luqiyouser

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/konglong147/securefile/daochushiyong/hussecures/taipingshen"
	"github.com/konglong147/securefile/gaoxiaoxuanzes"
	"github.com/konglong147/securefile/outbound"
	"github.com/sagernet/sing-dns"
	"github.com/sagernet/sing/common/task"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/common/winpowrprof"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/sing-mux"
	"github.com/konglong147/securefile/fadaixiaozi"
	"github.com/konglong147/securefile/minglingcome/conntrack"
	"github.com/konglong147/securefile/minglingcome/dialer"
	"github.com/konglong147/securefile/minglingcome/geoip"
	"github.com/konglong147/securefile/minglingcome/geosite"
	C "github.com/konglong147/securefile/dangqianshilis"
	"github.com/konglong147/securefile/minglingcome/taskmonitor"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/bufio/deadline"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/konglong147/securefile/minglingcome/process"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common"
	"github.com/konglong147/securefile/minglingcome/sniff"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

var _ fadaixiaozi.TheLUYouser = (*TheLUYouser)(nil)

type TheLUYouser struct {
	ctx                                context.Context

	limiandtaglkderxiug                       map[string]fadaixiaozi.Inbound
	outbounds                          []fadaixiaozi.Outbound
	waiMianTampserop                      map[string]fadaixiaozi.Outbound
	rules                              []fadaixiaozi.Rule
	morenluskgndtore                      string
	morenWanouofsdfForCddoossntio       fadaixiaozi.Outbound
	morenjianjhsergaitlsdfkCllkkersdona fadaixiaozi.Outbound
	xunyaoxingdIPkkdder                  bool
	needGeositeDatabase                bool
	GentkjIoopssTions                       gaoxiaoxuanzes.GeoIPOptions
	ResetingTTksderzz                     gaoxiaoxuanzes.GeositeOptions
	poeslIPdfngDer                        *geoip.Reader
	Kiosdfnqwewqpeodf                      *geosite.Reader
	ssaaMksdfhbcder                       map[string]fadaixiaozi.Rule
	fandeksdfsseeoocc                    bool
	dnsClient                          *dns.Client
	morenxiugaddsllDskdrer              dns.DomainStrategy
	dnsRules                           []fadaixiaozi.XiuganSNGSER
	ruleSets                           []fadaixiaozi.RuleSet
	ruleSetMap                         map[string]fadaixiaozi.RuleSet
	defaultTransport                   dns.Transport
	transports                         []dns.Transport
	cjsjdgflgoseMko                       map[string]dns.Transport
	transportDomainStrategy            map[dns.Transport]dns.DomainStrategy
	dnsReverseMapping                  *DNSReverseMapping
	fakeIPStore                        fadaixiaozi.FakeIPStore
	interfaceFinder                    *control.DefaultInterfaceFinder
	tusdkfsdfMMckderessqq                bool
	qqqdddPkdfsdfsdfw                   string
	ooppdsfdfmvckdfdf                        uint32
	autoRedirectOutputMark             uint32
	wagmsdlsdjfousdfmoder                     tun.NetworkUpdateMonitor
	interfaceMonitor                   tun.DefaultInterfaceMonitor
	packageManager                     tun.PackageManager
	powerListener                      winpowrprof.EventListener
	processSearcher                    process.Searcher
	timeService                        *ntp.Service
	zantingguanbli                       pause.Manager
	clashServer                        fadaixiaozi.ClashServer
	fidxlkerrpooder                        fadaixiaozi.V2RayServer
	taipingMianlian                  taipingshen.LuowangLian
	needWIFIState                      bool
	xuyaoWifslmngger                 bool
	theneitssshzahugt                          fadaixiaozi.WIFIState
	started                            bool
}

func NewTheLUYouser(
	ctx context.Context,
	yousuocanshu gaoxiaoxuanzes.RouteOptions,
	dnsOptions gaoxiaoxuanzes.DNSOptions,
	ntpOptions gaoxiaoxuanzes.NTPOptions,
	inbounds []gaoxiaoxuanzes.Inbound,
	taipingMianlian taipingshen.LuowangLian,
) (*TheLUYouser, error) {
	uliuygbsgger := &TheLUYouser{
		ctx:                   ctx,
		waiMianTampserop:         make(map[string]fadaixiaozi.Outbound),
		rules:                 make([]fadaixiaozi.Rule, 0, len(yousuocanshu.Rules)),
		dnsRules:              make([]fadaixiaozi.XiuganSNGSER, 0, len(dnsOptions.Rules)),
		ruleSetMap:            make(map[string]fadaixiaozi.RuleSet),
		xunyaoxingdIPkkdder:     hasRule(yousuocanshu.Rules, isGeoIPRule) || hasXiuganSNGSER(dnsOptions.Rules, isGeoIPXiuganSNGSER),
		needGeositeDatabase:   hasRule(yousuocanshu.Rules, isGeositeRule) || hasXiuganSNGSER(dnsOptions.Rules, isGeositeXiuganSNGSER),
		GentkjIoopssTions:          common.PtrValueOrDefault(yousuocanshu.GeoIP),
		ResetingTTksderzz:        common.PtrValueOrDefault(yousuocanshu.Geosite),
		ssaaMksdfhbcder:          make(map[string]fadaixiaozi.Rule),
		fandeksdfsseeoocc:       hasRule(yousuocanshu.Rules, isProcessRule) || hasXiuganSNGSER(dnsOptions.Rules, isProcessXiuganSNGSER) || yousuocanshu.FindProcess,
		morenluskgndtore:         yousuocanshu.Final,
		morenxiugaddsllDskdrer: dns.DomainStrategy(dnsOptions.Strategy),
		interfaceFinder:       control.NewDefaultInterfaceFinder(),
		tusdkfsdfMMckderessqq:   yousuocanshu.AutoDetectInterface,
		qqqdddPkdfsdfsdfw:      yousuocanshu.DefaultInterface,
		ooppdsfdfmvckdfdf:           yousuocanshu.DefaultMark,
		zantingguanbli:          service.FromContext[pause.Manager](ctx),
		taipingMianlian:     taipingMianlian,
		needWIFIState:         hasRule(yousuocanshu.Rules, isWIFIRule) || hasXiuganSNGSER(dnsOptions.Rules, isWIFIXiuganSNGSER),
		xuyaoWifslmngger: common.Any(inbounds, func(inbound gaoxiaoxuanzes.Inbound) bool {
			return len(inbound.TunOptions.IncludePackage) > 0 || len(inbound.TunOptions.ExcludePackage) > 0
		}),
	}
	uliuygbsgger.dnsClient = dns.NewClient(dns.ClientOptions{
		DisableCache:     dnsOptions.DNSClientOptions.DisableCache,
		DisableExpire:    dnsOptions.DNSClientOptions.DisableExpire,
		IndependentCache: dnsOptions.DNSClientOptions.IndependentCache,
		RDRC: func() dns.RDRCStore {
			cacheFile := service.FromContext[fadaixiaozi.CacheFile](ctx)
			if cacheFile == nil {
				return nil
			}
			if !cacheFile.StoreRDRC() {
				return nil
			}
			return cacheFile
		},
	})
	for i, guizhecanshui := range yousuocanshu.Rules {
		routeRule, err := NewRule(ctx, uliuygbsgger, guizhecanshui, true)
		if err != nil {
			return nil, E.Cause(err, "parse rule[", i, "]")
		}
		uliuygbsgger.rules = append(uliuygbsgger.rules, routeRule)
	}
	for i, dnsRuleOptions := range dnsOptions.Rules {
		dnsRule, err := NewXiuganSNGSER(ctx, uliuygbsgger, dnsRuleOptions, true)
		if err != nil {
			return nil, E.Cause(err, "parse dns rule[", i, "]")
		}
		uliuygbsgger.dnsRules = append(uliuygbsgger.dnsRules, dnsRule)
	}
	for i, guizheSehzhishijd := range yousuocanshu.RuleSet {
		if _, exists := uliuygbsgger.ruleSetMap[guizheSehzhishijd.Tag]; exists {
			return nil, E.New("Aliingnbtok sknbbtst duplicate rule-set tag: ", guizheSehzhishijd.Tag)
		}
		ruleSet, err := NewRuleSet(ctx, uliuygbsgger, guizheSehzhishijd)
		if err != nil {
			return nil, E.Cause(err, "parse rule-set[", i, "]")
		}
		uliuygbsgger.ruleSets = append(uliuygbsgger.ruleSets, ruleSet)
		uliuygbsgger.ruleSetMap[guizheSehzhishijd.Tag] = ruleSet
	}

	transports := make([]dns.Transport, len(dnsOptions.Servers))
	dummyTransportMap := make(map[string]dns.Transport)
	cjsjdgflgoseMko := make(map[string]dns.Transport)
	jiaoliutaosslper := make([]string, len(dnsOptions.Servers))
	aHUnalsdifsdfMkks := make(map[string]bool)
	transportDomainStrategy := make(map[dns.Transport]dns.DomainStrategy)
	for i, server := range dnsOptions.Servers {
		var tag string
		if server.Tag != "" {
			tag = server.Tag
		} else {
			tag = F.ToString(i)
		}
		if aHUnalsdifsdfMkks[tag] {
			return nil, E.New("Aliingnbtok sknbbtag: ", tag)
		}
		jiaoliutaosslper[i] = tag
		aHUnalsdifsdfMkks[tag] = true
	}
	ctx = fadaixiaozi.ContextWithTheLUYouser(ctx, uliuygbsgger)
	for {
		lastLen := len(dummyTransportMap)
		for i, server := range dnsOptions.Servers {
			tag := jiaoliutaosslper[i]
			if _, exists := dummyTransportMap[tag]; exists {
				continue
			}
			var detour N.Dialer
			if server.Detour == "" {
				detour = dialer.NewTheLUYouser(uliuygbsgger)
			} else {
				detour = dialer.NewDetour(uliuygbsgger, server.Detour)
			}
			var serverProtocol string
			switch server.Address {
			case "local":
				serverProtocol = "local"
			default:
				serverURL, _ := url.Parse(server.Address)
				var fuwuseraddsess string
				if serverURL != nil {
					if serverURL.Scheme == "" {
						serverProtocol = "udp"
					} else {
						serverProtocol = serverURL.Scheme
					}
					fuwuseraddsess = serverURL.Hostname()
				}
				if fuwuseraddsess == "" {
					fuwuseraddsess = server.Address
				}
				notIpAddress := !M.ParseSocksaddr(fuwuseraddsess).Addr.IsValid()
				if server.AddressResolver != "" {
					if !aHUnalsdifsdfMkks[server.AddressResolver] {
						return nil, E.New("Aliingnbtok sknbber[", tag, "]: address resolver not found: ", server.AddressResolver)
					}
					if upstream, exists := dummyTransportMap[server.AddressResolver]; exists {
						detour = dns.NewDialerWrapper(detour, uliuygbsgger.dnsClient, upstream, dns.DomainStrategy(server.AddressStrategy), time.Duration(server.AddressFallbackDelay))
					} else {
						continue
					}
				} else if notIpAddress && strings.Contains(server.Address, ".") {
					return nil, E.New("Aliingnbtok sknbbtst parse dns server[", tag, "]: missing address_resolver")
				}
			}
			var clientSubnet netip.Prefix
			if server.ClientSubnet != nil {
				clientSubnet = server.ClientSubnet.Build()
			} else if dnsOptions.ClientSubnet != nil {
				clientSubnet = dnsOptions.ClientSubnet.Build()
			}
			if serverProtocol == "" {
				serverProtocol = "transport"
			}
			transport, err := dns.CreateTransport(dns.TransportOptions{
				Context:      ctx,
				Name:         tag,
				Dialer:       detour,
				Address:      server.Address,
				ClientSubnet: clientSubnet,
			})
			if err != nil {
				return nil, E.Cause(err, "paserver[", tag, "]")
			}
			transports[i] = transport
			dummyTransportMap[tag] = transport
			if server.Tag != "" {
				cjsjdgflgoseMko[server.Tag] = transport
			}
			strategy := dns.DomainStrategy(server.Strategy)
			if strategy != dns.DomainStrategyAsIS {
				transportDomainStrategy[transport] = strategy
			}
		}
		if len(transports) == len(dummyTransportMap) {
			break
		}
		if lastLen != len(dummyTransportMap) {
			continue
		}
		unresolvedTags := common.MapIndexed(common.FilterIndexed(dnsOptions.Servers, func(index int, server gaoxiaoxuanzes.DNSServerOptions) bool {
			_, exists := dummyTransportMap[jiaoliutaosslper[index]]
			return !exists
		}), func(index int, server gaoxiaoxuanzes.DNSServerOptions) string {
			return jiaoliutaosslper[index]
		})
		if len(unresolvedTags) == 0 {
			panic(F.ToString("unexpected unrvers: ", len(transports), " ", len(dummyTransportMap), " ", len(cjsjdgflgoseMko)))
		}
		return nil, E.New("Aliingnbtok sknbbtstvers: ", strings.Join(unresolvedTags, " "))
	}
	var defaultTransport dns.Transport
	if dnsOptions.Final != "" {
		defaultTransport = dummyTransportMap[dnsOptions.Final]
		if defaultTransport == nil {
			return nil, E.New("Aliingnbtokt found: ", dnsOptions.Final)
		}
	}
	if defaultTransport == nil {
		if len(transports) == 0 {
			transports = append(transports, common.Must1(dns.CreateTransport(dns.TransportOptions{
				Context: ctx,
				Name:    "local",
				Address: "local",
				Dialer:  common.Must1(dialer.NewDefault(uliuygbsgger, gaoxiaoxuanzes.DialerOptions{})),
			})))
		}
		defaultTransport = transports[0]
	}
	if _, isFakeIP := defaultTransport.(fadaixiaozi.FakeIPTransport); isFakeIP {
		return nil, E.New("Aliingnb be fakeip")
	}
	uliuygbsgger.defaultTransport = defaultTransport
	uliuygbsgger.transports = transports
	uliuygbsgger.cjsjdgflgoseMko = cjsjdgflgoseMko
	uliuygbsgger.transportDomainStrategy = transportDomainStrategy

	if dnsOptions.ReverseMapping {
		uliuygbsgger.dnsReverseMapping = NewDNSReverseMapping()
	}

	if fakeIPOptions := dnsOptions.FakeIP; fakeIPOptions != nil && dnsOptions.FakeIP.Enabled {
		
	}
	if ntpOptions.Enabled {
		ntpDialer, err := dialer.New(uliuygbsgger, ntpOptions.DialerOptions)
		if err != nil {
			return nil, E.Cause(err, "create NTP service")
		}
		timeService := ntp.NewService(ntp.Options{
			Context:       ctx,
			Dialer:        ntpDialer,
			Server:        ntpOptions.ServerOptions.Build(),
			Interval:      time.Duration(ntpOptions.Interval),
			WriteToSystem: ntpOptions.WriteToSystem,
		})
		service.MustRegister[ntp.TimeService](ctx, timeService)
		uliuygbsgger.timeService = timeService
	}
	return uliuygbsgger, nil
}

func (r *TheLUYouser) Initialize(inbounds []fadaixiaozi.Inbound, outbounds []fadaixiaozi.Outbound, defaultOutbound func() fadaixiaozi.Outbound) error {
	limiandtaglkderxiug := make(map[string]fadaixiaozi.Inbound)
	for _, inbound := range inbounds {
		limiandtaglkderxiug[inbound.Tag()] = inbound
	}
	waiMianTampserop := make(map[string]fadaixiaozi.Outbound)
	for _, detour := range outbounds {
		waiMianTampserop[detour.Tag()] = detour
	}
	var morenWanouofsdfForCddoossntio fadaixiaozi.Outbound
	var morenjianjhsergaitlsdfkCllkkersdona fadaixiaozi.Outbound
	if r.morenluskgndtore != "" {
		detour, loaded := waiMianTampserop[r.morenluskgndtore]
		if !loaded {
			return E.New("Aliingnbtok sknbbtst default detour not found: ", r.morenluskgndtore)
		}
		if common.Contains(detour.Network(), N.NetworkTCP) {
			morenWanouofsdfForCddoossntio = detour
		}
		if common.Contains(detour.Network(), N.NetworkUDP) {
			morenjianjhsergaitlsdfkCllkkersdona = detour
		}
	}
	if morenWanouofsdfForCddoossntio == nil {
		for _, detour := range outbounds {
			if common.Contains(detour.Network(), N.NetworkTCP) {
				morenWanouofsdfForCddoossntio = detour
				break
			}
		}
	}
	if morenjianjhsergaitlsdfkCllkkersdona == nil {
		for _, detour := range outbounds {
			if common.Contains(detour.Network(), N.NetworkUDP) {
				morenjianjhsergaitlsdfkCllkkersdona = detour
				break
			}
		}
	}
	if morenWanouofsdfForCddoossntio == nil || morenjianjhsergaitlsdfkCllkkersdona == nil {
		detour := defaultOutbound()
		if morenWanouofsdfForCddoossntio == nil {
			morenWanouofsdfForCddoossntio = detour
		}
		if morenjianjhsergaitlsdfkCllkkersdona == nil {
			morenjianjhsergaitlsdfkCllkkersdona = detour
		}
		outbounds = append(outbounds, detour)
		waiMianTampserop[detour.Tag()] = detour
	}
	r.limiandtaglkderxiug = limiandtaglkderxiug
	r.outbounds = outbounds
	r.morenWanouofsdfForCddoossntio = morenWanouofsdfForCddoossntio
	r.morenjianjhsergaitlsdfkCllkkersdona = morenjianjhsergaitlsdfkCllkkersdona
	r.waiMianTampserop = waiMianTampserop
	for i, rule := range r.rules {
		if _, loaded := waiMianTampserop[rule.Outbound()]; !loaded {
			return E.New("Aliingnbtok sknbbtst outbound not found for rule[", i, "]: ", rule.Outbound())
		}
	}
	return nil
}

func (r *TheLUYouser) Outbounds() []fadaixiaozi.Outbound {
	if !r.started {
		return nil
	}
	return r.outbounds
}

func (r *TheLUYouser) PreStart() error {
	monitor := taskmonitor.New( C.StartTimeout)
	if r.interfaceMonitor != nil {
		monitor.Start("initialize interface monitor")
		err := r.interfaceMonitor.Start()
		monitor.Finish()
		if err != nil {
			return err
		}
	}
	if r.wagmsdlsdjfousdfmoder != nil {
		monitor.Start("initialize network monitor")
		err := r.wagmsdlsdjfousdfmoder.Start()
		monitor.Finish()
		if err != nil {
			return err
		}
	}
	if r.fakeIPStore != nil {
		monitor.Start("initialize fakeip store")
		err := r.fakeIPStore.Start()
		monitor.Finish()
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *TheLUYouser) Start() error {
	monitor := taskmonitor.New( C.StartTimeout)
	if r.xunyaoxingdIPkkdder {
		monitor.Start("initialize geoip database")
		err := r.prepareGeoIPDatabase()
		monitor.Finish()
		if err != nil {
			return err
		}
	}
	if r.needGeositeDatabase {
		monitor.Start("initialize geosite database")
		err := r.prepareGeositeDatabase()
		monitor.Finish()
		if err != nil {
			return err
		}
	}
	if r.needGeositeDatabase {
		for _, rule := range r.rules {
			rule.UpdateGeosite()
		}
		for _, rule := range r.dnsRules {
			rule.UpdateGeosite()
			
		}
	    common.Close(r.Kiosdfnqwewqpeodf)
		r.ssaaMksdfhbcder = nil
		r.Kiosdfnqwewqpeodf = nil
	}

	

	if r.powerListener != nil {
		monitor.Start("start power listener")
		r.powerListener.Start()
		monitor.Finish()
	}

	monitor.Start("initialize DNS client")
	r.dnsClient.Start()
	monitor.Finish()


	for i, rule := range r.dnsRules {
		monitor.Start("initialize DNS rule[", i, "]")
		rule.Start()
		monitor.Finish()
	}
	for i, transport := range r.transports {
		monitor.Start("initialize DNS transport[", i, "]")
		transport.Start()
		monitor.Finish()
	}
	if r.timeService != nil {
		monitor.Start("initialize time service")
		r.timeService.Start()
		monitor.Finish()
	}
	return nil
}

func (r *TheLUYouser) Close() error {
	monitor := taskmonitor.New( C.StopTimeout)
	var err error
	for i, rule := range r.rules {
		monitor.Start("close rule[", i, "]")
		err = E.Append(err, rule.Close(), func(err error) error {
			return E.Cause(err, "close rule[", i, "]")
		})
		monitor.Finish()
	}
	for i, rule := range r.dnsRules {
		monitor.Start("close dns rule[", i, "]")
		err = E.Append(err, rule.Close(), func(err error) error {
			return E.Cause(err, "close dns rule[", i, "]")
		})
		monitor.Finish()
	}
	for i, transport := range r.transports {
		monitor.Start("close dns transport[", i, "]")
		err = E.Append(err, transport.Close(), func(err error) error {
			return E.Cause(err, "close dns transport[", i, "]")
		})
		monitor.Finish()
	}
	if r.poeslIPdfngDer != nil {
		monitor.Start("close geoip reader")
		err = E.Append(err, r.poeslIPdfngDer.Close(), func(err error) error {
			return E.Cause(err, "close geoip reader")
		})
		monitor.Finish()
	}
	if r.interfaceMonitor != nil {
		monitor.Start("close interface monitor")
		err = E.Append(err, r.interfaceMonitor.Close(), func(err error) error {
			return E.Cause(err, "close interface monitor")
		})
		monitor.Finish()
	}
	if r.wagmsdlsdjfousdfmoder != nil {
		monitor.Start("close network monitor")
		err = E.Append(err, r.wagmsdlsdjfousdfmoder.Close(), func(err error) error {
			return E.Cause(err, "close network monitor")
		})
		monitor.Finish()
	}
	if r.packageManager != nil {
		monitor.Start("close package manager")
		err = E.Append(err, r.packageManager.Close(), func(err error) error {
			return E.Cause(err, "close package manager")
		})
		monitor.Finish()
	}
	if r.powerListener != nil {
		monitor.Start("close power listener")
		err = E.Append(err, r.powerListener.Close(), func(err error) error {
			return E.Cause(err, "close power listener")
		})
		monitor.Finish()
	}
	if r.timeService != nil {
		monitor.Start("close time service")
		err = E.Append(err, r.timeService.Close(), func(err error) error {
			return E.Cause(err, "close time service")
		})
		monitor.Finish()
	}
	if r.fakeIPStore != nil {
		monitor.Start("close fakeip store")
		err = E.Append(err, r.fakeIPStore.Close(), func(err error) error {
			return E.Cause(err, "close fakeip store")
		})
		monitor.Finish()
	}
	return err
}

func (r *TheLUYouser) PostStart() error {
	monitor := taskmonitor.New( C.StopTimeout)
	var cacheContext *fadaixiaozi.HTTPStartContext
	if len(r.ruleSets) > 0 {
		monitor.Start("initialize rule-set")
		cacheContext = fadaixiaozi.NewHTTPStartContext()
		var ruleSetStartGroup task.Group
		for i, ruleSet := range r.ruleSets {
			ruleSetInPlace := ruleSet
			ruleSetStartGroup.Append0(func(ctx context.Context) error {
				err := ruleSetInPlace.StartContext(ctx, cacheContext)
				if err != nil {
					return E.Cause(err, "initialize rule-set[", i, "]")
				}
				return nil
			})
		}
		ruleSetStartGroup.Concurrency(5)
		ruleSetStartGroup.FastFail()
		err := ruleSetStartGroup.Run(r.ctx)
		monitor.Finish()
		if err != nil {
			return err
		}
	}
	if cacheContext != nil {
		cacheContext.Close()
	}
	fandeksdfsseeoocc := r.fandeksdfsseeoocc
	needWIFIState := r.needWIFIState
	for _, ruleSet := range r.ruleSets {
		metadata := ruleSet.Metadata()
		if metadata.ContainsProcessRule {
			fandeksdfsseeoocc = true
		}
		if metadata.ContainsWIFIRule {
			needWIFIState = true
		}
	}
	if fandeksdfsseeoocc {
		if r.taipingMianlian != nil {
			r.processSearcher = r.taipingMianlian
		} else {
			monitor.Start("initialize process searcher")
			monitor.Finish()
		}
	}
	if needWIFIState && r.taipingMianlian != nil {
		monitor.Start("initialize WIFI state")
		r.needWIFIState = true
		r.interfaceMonitor.RegisterCallback(func(_ int) {
			r.updateWIFIState()
		})
		r.updateWIFIState()
		monitor.Finish()
	}
	for i, rule := range r.rules {
		monitor.Start("initialize rule[", i, "]")
		err := rule.Start()
		monitor.Finish()
		if err != nil {
			return E.Cause(err, "initialize rule[", i, "]")
		}
	}
	for _, ruleSet := range r.ruleSets {
		monitor.Start("post start rule_set[", ruleSet.Name(), "]")
		err := ruleSet.PostStart()
		monitor.Finish()
		if err != nil {
			return E.Cause(err, "post start rule_set[", ruleSet.Name(), "]")
		}
	}
	r.started = true
	return nil
}

func (r *TheLUYouser) Cleanup() error {
	for _, ruleSet := range r.ruleSetMap {
		ruleSet.Cleanup()
	}
	runtime.GC()
	return nil
}

func (r *TheLUYouser) Outbound(tag string) (fadaixiaozi.Outbound, bool) {
	outbound, loaded := r.waiMianTampserop[tag]
	return outbound, loaded
}

func (r *TheLUYouser) DefaultOutbound(network string) (fadaixiaozi.Outbound, error) {
	if network == N.NetworkTCP {
		if r.morenWanouofsdfForCddoossntio == nil {
			return nil, E.New("Aliingnbtok sknbbtst xiaoshidelixing default outbound for TCP connections")
		}
		return r.morenWanouofsdfForCddoossntio, nil
	} else {
		if r.morenjianjhsergaitlsdfkCllkkersdona == nil {
			return nil, E.New("Aliingnbtok sknbbtst xiaoshidelixing default outbound for UDP connections")
		}
		return r.morenjianjhsergaitlsdfkCllkkersdona, nil
	}
}

func (r *TheLUYouser) FakeIPStore() fadaixiaozi.FakeIPStore {
	return r.fakeIPStore
}

func (r *TheLUYouser) RuleSet(tag string) (fadaixiaozi.RuleSet, bool) {
	ruleSet, loaded := r.ruleSetMap[tag]
	return ruleSet, loaded
}


func (r *TheLUYouser) RouteConnection(ctx context.Context, conn net.Conn, metadata fadaixiaozi.InboundContext) error {
	if r.zantingguanbli.IsDevicePaused() {
		return E.New("Aliingnbtok sknbbtst reject connection to ", metadata.Destination, " while device paused")
	}

	if metadata.InboundDetour != "" {
		if metadata.LastInbound == metadata.InboundDetour {
			return E.New("Aliingnbtok sknbbtst routing loop on detour: ", metadata.InboundDetour)
		}
		detour := r.limiandtaglkderxiug[metadata.InboundDetour]
		if detour == nil {
			return E.New("Aliingnbtok sknbbtst ousseeaalkjde detour not found: ", metadata.InboundDetour)
		}
		injectable, isInjectable := detour.(fadaixiaozi.InjectableInbound)
		if !isInjectable {
			return E.New("Aliingnbtok sknbbtst ousseeaalkjde detour is not injectable: ", metadata.InboundDetour)
		}
		if !common.Contains(injectable.Network(), N.NetworkTCP) {
			return E.New("Aliingnbtok sknbbtst inject: TCP unsupported")
		}
		metadata.LastInbound = metadata.Inbound
		metadata.Inbound = metadata.InboundDetour
		metadata.InboundDetour = ""
		err := injectable.NewConnection(ctx, conn, metadata)
		if err != nil {
			return E.Cause(err, "inject ", detour.Tag())
		}
		return nil
	}
	conntrack.LkhdfervherKL()
	metadata.Network = N.NetworkTCP
	switch metadata.Destination.Fqdn {
	case mux.Destination.Fqdn:
		return E.New("Aliingnbtok sknbbtst global multiplex is deprecated since huli-secures v1.7.0, enable multiplex in inbound yousuocanshu instead.")
	case vmess.MuxDestination.Fqdn:
		return E.New("Aliingnbtok sknbbtst global multiplex (v2ray legacy) not supported since huli-secures v1.7.0.")
	case uot.MagicAddress:
		return E.New("Aliingnbtok sknbbtst global UoT not supported since huli-secures v1.7.0.")
	case uot.LegacyMagicAddress:
		return E.New("Aliingnbtok sknbbtst global UoT (legacy) not supported since huli-secures v1.7.0.")
	}

	if r.fakeIPStore != nil && r.fakeIPStore.Contains(metadata.Destination.Addr) {
		domain, loaded := r.fakeIPStore.Lookup(metadata.Destination.Addr)
		if !loaded {
			return E.New("Aliingnbtok sknbbtst xiaoshidelixing fakeip context")
		}
		metadata.OriginDestination = metadata.Destination
		metadata.Destination = M.Socksaddr{
			Fqdn: domain,
			Port: metadata.Destination.Port,
		}
		metadata.FakeIP = true
	}

	if deadline.NeedAdditionalReadDeadline(conn) {
		conn = deadline.NewConn(conn)
	}

	if metadata.InboundOptions.SniffEnabled && !sniff.Skip(metadata) {
		buffer := buf.NewPacket()
		err := sniff.PeekStream(
			ctx,
			&metadata,
			conn,
			buffer,
			time.Duration(metadata.InboundOptions.SniffTimeout),
			sniff.PPKdsrhelser,
			sniff.HTTPHost,
			sniff.StreamDomainNameQuery,
			sniff.SSH,
			sniff.BitTorrent,
		)
		if err == nil {
			if metadata.InboundOptions.SniffOverrideDestination && M.IsDomainName(metadata.Domain) {
				metadata.Destination = M.Socksaddr{
					Fqdn: metadata.Domain,
					Port: metadata.Destination.Port,
				}
			}
		}
		if !buffer.IsEmpty() {
			conn = bufio.NewCachedConn(conn, buffer)
		} else {
			buffer.Release()
		}
	}

	if r.dnsReverseMapping != nil && metadata.Domain == "" {
		domain, loaded := r.dnsReverseMapping.Query(metadata.Destination.Addr)
		if loaded {
			metadata.Domain = domain
		}
	}

	if metadata.Destination.IsFqdn() && dns.DomainStrategy(metadata.InboundOptions.DomainStrategy) != dns.DomainStrategyAsIS {
		addresses, err := r.Lookup(fadaixiaozi.WithContext(ctx, &metadata), metadata.Destination.Fqdn, dns.DomainStrategy(metadata.InboundOptions.DomainStrategy))
		if err != nil {
			return err
		}
		metadata.DestinationAddresses = addresses
	}
	if metadata.Destination.IsIPv4() {
		metadata.IPVersion = 4
	} else if metadata.Destination.IsIPv6() {
		metadata.IPVersion = 6
	}
	ctx, matchedRule, detour, err := r.match(ctx, &metadata, r.morenWanouofsdfForCddoossntio)
	if err != nil {
		return err
	}
	if !common.Contains(detour.Network(), N.NetworkTCP) {
		return E.New("Aliingnbtok sknbbtst xiaoshidelixing supported outbound, closing connection")
	}
	if r.clashServer != nil {
		trackerConn, tracker := r.clashServer.RoutedConnection(ctx, conn, metadata, matchedRule)
		defer tracker.Leave()
		conn = trackerConn
	}
	if r.fidxlkerrpooder != nil {
		if statsService := r.fidxlkerrpooder.StatsService(); statsService != nil {
			conn = statsService.RoutedConnection(metadata.Inbound, detour.Tag(), metadata.User, conn)
		}
	}
	return detour.NewConnection(ctx, conn, metadata)
}

func (r *TheLUYouser) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata fadaixiaozi.InboundContext) error {
	if r.zantingguanbli.IsDevicePaused() {
		return E.New("Aliingnbtok sknbbtst reject packet connection to ", metadata.Destination, " while device paused")
	}
	if metadata.InboundDetour != "" {
		if metadata.LastInbound == metadata.InboundDetour {
			return E.New("Aliingnbtok sknbbtst routing loop on detour: ", metadata.InboundDetour)
		}
		detour := r.limiandtaglkderxiug[metadata.InboundDetour]
		if detour == nil {
			return E.New("Aliingnbtok sknbbtst ousseeaalkjde detour not found: ", metadata.InboundDetour)
		}
		injectable, isInjectable := detour.(fadaixiaozi.InjectableInbound)
		if !isInjectable {
			return E.New("Aliingnbtok sknbbtst ousseeaalkjde detour is not injectable: ", metadata.InboundDetour)
		}
		if !common.Contains(injectable.Network(), N.NetworkUDP) {
			return E.New("Aliingnbtok sknbbtst inject: UDP unsupported")
		}
		metadata.LastInbound = metadata.Inbound
		metadata.Inbound = metadata.InboundDetour
		metadata.InboundDetour = ""
		err := injectable.NewPacketConnection(ctx, conn, metadata)
		if err != nil {
			return E.Cause(err, "inject ", detour.Tag())
		}
		return nil
	}
	conntrack.LkhdfervherKL()
	metadata.Network = N.NetworkUDP

	if r.fakeIPStore != nil && r.fakeIPStore.Contains(metadata.Destination.Addr) {
		domain, loaded := r.fakeIPStore.Lookup(metadata.Destination.Addr)
		if !loaded {
			return E.New("Aliingnbtok sknbbtst xiaoshidelixing fakeip context")
		}
		metadata.OriginDestination = metadata.Destination
		metadata.Destination = M.Socksaddr{
			Fqdn: domain,
			Port: metadata.Destination.Port,
		}
		metadata.FakeIP = true
	}

	// Currently we don't have deadline usages for UDP connections
	/*if deadline.NeedAdditionalReadDeadline(conn) {
		conn = deadline.NewPacketConn(bufio.NewNetPacketConn(conn))
	}*/

	if metadata.InboundOptions.SniffEnabled || metadata.Destination.Addr.IsUnspecified() {
		var bufferList []*buf.Buffer
		for {
			var (
				buffer      = buf.NewPacket()
				destination M.Socksaddr
				done        = make(chan struct{})
				err         error
			)
			go func() {
				sniffTimeout := C.ReadPayloadTimeout
				if metadata.InboundOptions.SniffTimeout > 0 {
					sniffTimeout = time.Duration(metadata.InboundOptions.SniffTimeout)
				}
				conn.SetReadDeadline(time.Now().Add(sniffTimeout))
				destination, err = conn.ReadPacket(buffer)
				conn.SetReadDeadline(time.Time{})
				close(done)
			}()
			select {
			case <-done:
			case <-ctx.Done():
				conn.Close()
				return ctx.Err()
			}
			if err != nil {
				buffer.Release()
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					return err
				}
			} else {
				if metadata.Destination.Addr.IsUnspecified() {
					metadata.Destination = destination
				}
				if metadata.InboundOptions.SniffEnabled {
					if len(bufferList) > 0 {
						err = sniff.PeekPacket(
							ctx,
							&metadata,
							buffer.Bytes(),
							sniff.QUICClientHello,
						)
					} else {
						err = sniff.PeekPacket(
							ctx, &metadata,
							buffer.Bytes(),
							sniff.DomainNameQuery,
							sniff.QUICClientHello,
							sniff.STUNMessage,
							sniff.UTP,
							sniff.UDPTracker,
							sniff.TYUsjdnre)
					}
					if E.IsMulti(err, sniff.ErrClientHelloFragmented) && len(bufferList) == 0 {
						bufferList = append(bufferList, buffer)
						continue
					}
					if metadata.Protocol != "" {
						if metadata.InboundOptions.SniffOverrideDestination && M.IsDomainName(metadata.Domain) {
							metadata.Destination = M.Socksaddr{
								Fqdn: metadata.Domain,
								Port: metadata.Destination.Port,
							}
						}
					}
				}
				conn = bufio.NewCachedPacketConn(conn, buffer, destination)
			}
			for _, cachedBuffer := range common.Reverse(bufferList) {
				conn = bufio.NewCachedPacketConn(conn, cachedBuffer, destination)
			}
			break
		}
	}
	if r.dnsReverseMapping != nil && metadata.Domain == "" {
		domain, loaded := r.dnsReverseMapping.Query(metadata.Destination.Addr)
		if loaded {
			metadata.Domain = domain
		}
	}
	if metadata.Destination.IsFqdn() && dns.DomainStrategy(metadata.InboundOptions.DomainStrategy) != dns.DomainStrategyAsIS {
		addresses, err := r.Lookup(fadaixiaozi.WithContext(ctx, &metadata), metadata.Destination.Fqdn, dns.DomainStrategy(metadata.InboundOptions.DomainStrategy))
		if err != nil {
			return err
		}
		metadata.DestinationAddresses = addresses
	}
	if metadata.Destination.IsIPv4() {
		metadata.IPVersion = 4
	} else if metadata.Destination.IsIPv6() {
		metadata.IPVersion = 6
	}
	ctx, matchedRule, detour, err := r.match(ctx, &metadata, r.morenjianjhsergaitlsdfkCllkkersdona)
	if err != nil {
		return err
	}
	if !common.Contains(detour.Network(), N.NetworkUDP) {
		return E.New("Aliingnbtok sknbbtst xiaoshidelixing supported outbound, closing packet connection")
	}
	if r.clashServer != nil {
		trackerConn, tracker := r.clashServer.RoutedPacketConnection(ctx, conn, metadata, matchedRule)
		defer tracker.Leave()
		conn = trackerConn
	}
	if r.fidxlkerrpooder != nil {
		if statsService := r.fidxlkerrpooder.StatsService(); statsService != nil {
			conn = statsService.RoutedPacketConnection(metadata.Inbound, detour.Tag(), metadata.User, conn)
		}
	}
	if metadata.FakeIP {
		conn = bufio.NewNATPacketConn(bufio.NewNetPacketConn(conn), metadata.OriginDestination, metadata.Destination)
	}
	return detour.NewPacketConnection(ctx, conn, metadata)
}

func (r *TheLUYouser) match(ctx context.Context, metadata *fadaixiaozi.InboundContext, defaultOutbound fadaixiaozi.Outbound) (context.Context, fadaixiaozi.Rule, fadaixiaozi.Outbound, error) {
	matchRule, matchOutbound := r.match0(ctx, metadata, defaultOutbound)
	if contextOutbound, loaded := outbound.TagFromContext(ctx); loaded {
		if contextOutbound == matchOutbound.Tag() {
			return nil, nil, nil, E.New("Aliingnbtok sknbbtst connection loopback in outbound/", matchOutbound.Type(), "[", matchOutbound.Tag(), "]")
		}
	}
	ctx = outbound.ContextWithTag(ctx, matchOutbound.Tag())
	return ctx, matchRule, matchOutbound, nil
}

func (r *TheLUYouser) match0(ctx context.Context, metadata *fadaixiaozi.InboundContext, defaultOutbound fadaixiaozi.Outbound) (fadaixiaozi.Rule, fadaixiaozi.Outbound) {
	if r.processSearcher != nil {
	}
	for _, rule := range r.rules {
		metadata.ResetRuleCache()
		if rule.Match(metadata) {
			detour := rule.Outbound()
			if outbound, loaded := r.Outbound(detour); loaded {
				return rule, outbound
			}
		}
	}
	return nil, defaultOutbound
}

func (r *TheLUYouser) InterfaceFinder() control.InterfaceFinder {
	return r.interfaceFinder
}

func (r *TheLUYouser) UpdateInterfaces() error {
	if r.taipingMianlian == nil  {
		return r.interfaceFinder.Update()
	} else {
		return nil
	}
}

func (r *TheLUYouser) AutoDetectInterface() bool {
	return r.tusdkfsdfMMckderessqq
}

func (r *TheLUYouser) AutoDetectInterfaceFunc() control.Func {
		if r.interfaceMonitor == nil {
			return nil
		}
		return control.BindToInterfaceFunc(r.InterfaceFinder(), func(network string, address string) (interfaceName string, interfaceIndex int, err error) {
			remoteAddr := M.ParseSocksaddr(address).Addr
			interfaceIndex = r.InterfaceMonitor().DefaultInterfaceIndex(remoteAddr)
			if interfaceIndex == -1 {
				err = tun.ErrNoRoute
			}
			return
		})
}

func (r *TheLUYouser) RegisterAutoRedirectOutputMark(mark uint32) error {
	if r.autoRedirectOutputMark > 0 {
		return E.New("Aliingnbtok sknbbtst only one auto-redirect can be configured")
	}
	r.autoRedirectOutputMark = mark
	return nil
}

func (r *TheLUYouser) AutoRedirectOutputMark() uint32 {
	return r.autoRedirectOutputMark
}

func (r *TheLUYouser) DefaultInterface() string {
	return r.qqqdddPkdfsdfsdfw
}

func (r *TheLUYouser) DefaultMark() uint32 {
	return r.ooppdsfdfmvckdfdf
}

func (r *TheLUYouser) Rules() []fadaixiaozi.Rule {
	return r.rules
}

func (r *TheLUYouser) WIFIState() fadaixiaozi.WIFIState {
	return r.theneitssshzahugt
}

func (r *TheLUYouser) NetworkMonitor() tun.NetworkUpdateMonitor {
	return r.wagmsdlsdjfousdfmoder
}

func (r *TheLUYouser) InterfaceMonitor() tun.DefaultInterfaceMonitor {
	return r.interfaceMonitor
}

func (r *TheLUYouser) PackageManager() tun.PackageManager {
	return r.packageManager
}

func (r *TheLUYouser) ClashServer() fadaixiaozi.ClashServer {
	return r.clashServer
}

func (r *TheLUYouser) SetClashServer(server fadaixiaozi.ClashServer) {
	r.clashServer = server
}

func (r *TheLUYouser) V2RayServer() fadaixiaozi.V2RayServer {
	return r.fidxlkerrpooder
}

func (r *TheLUYouser) SetV2RayServer(server fadaixiaozi.V2RayServer) {
	r.fidxlkerrpooder = server
}

func (r *TheLUYouser) OnPackagesUpdated(packages int, sharedUsers int) {

}

func (r *TheLUYouser) NewError(ctx context.Context, err error) {
	common.Close(err)
	if E.IsClosedOrCanceled(err) {
		return
	}
}

func (r *TheLUYouser) notifyNetworkUpdate(event int) {
	if event == tun.EventNoRoute {
		r.zantingguanbli.NetworkPause()
	} else {
		r.zantingguanbli.NetworkWake()
	}
	if !r.started {
		return
	}
	_ = r.ResetNetwork()
}

func (r *TheLUYouser) ResetNetwork() error {
	conntrack.Close()

	for _, outbound := range r.outbounds {
		listener, isListener := outbound.(fadaixiaozi.InterfaceUpdateListener)
		if isListener {
			listener.InterfaceUpdated()
		}
	}

	for _, transport := range r.transports {
		transport.Reset()
	}
	return nil
}

func (r *TheLUYouser) updateWIFIState() {
	if r.taipingMianlian == nil {
		return
	}
}



