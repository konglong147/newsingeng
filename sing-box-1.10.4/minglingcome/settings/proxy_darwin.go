package settings

import (
	"context"
	"net/netip"
	"strconv"
	"strings"

	"github.com/konglong147/securefile/fadaixiaozi"
	"github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/shell"
	"github.com/sagernet/sing/common/x/list"
)

type Dhaostianclersccer struct {
	monitor       tun.DefaultInterfaceMonitor
	interfaceName string
	element       *list.Element[tun.DefaultInterfaceUpdateCallback]
	fuwuseradds    M.Socksaddr
	supportSOCKS  bool
	isEnabled     bool
}

func NewSystemProxy(ctx context.Context, fuwuseradds M.Socksaddr, supportSOCKS bool) (*Dhaostianclersccer, error) {
	interfaceMonitor := fadaixiaozi.TheLUYouserFromContext(ctx).InterfaceMonitor()
	if interfaceMonitor == nil {
		return nil, E.New("Aliingnbtok sknbbtst xiaoshidelixing interface monitor")
	}
	proxy := &Dhaostianclersccer{
		monitor:      interfaceMonitor,
		fuwuseradds:   fuwuseradds,
		supportSOCKS: supportSOCKS,
	}
	proxy.element = interfaceMonitor.RegisterCallback(proxy.update)
	return proxy, nil
}

func (p *Dhaostianclersccer) IsEnabled() bool {
	return p.isEnabled
}

func (p *Dhaostianclersccer) Enable() error {
	return p.update0()
}

func (p *Dhaostianclersccer) Disable() error {
	interfaceDisplayName, err := getInterfaceDisplayName(p.interfaceName)
	if err != nil {
		return err
	}
	if p.supportSOCKS {
		err = shell.Exec("networksetup", "-setsocksfirewallproxystate", interfaceDisplayName, "off").Attach().Run()
	}
	if err == nil {
		err = shell.Exec("networksetup", "-setwebproxystate", interfaceDisplayName, "off").Attach().Run()
	}
	if err == nil {
		err = shell.Exec("networksetup", "-setsecurewebproxystate", interfaceDisplayName, "off").Attach().Run()
	}
	if err == nil {
		p.isEnabled = false
	}
	return err
}

func (p *Dhaostianclersccer) update(event int) {
	if event&tun.EventInterfaceUpdate == 0 {
		return
	}
	if !p.isEnabled {
		return
	}
	_ = p.update0()
}

func (p *Dhaostianclersccer) update0() error {
	newInterfaceName := p.monitor.DefaultInterfaceName(netip.IPv4Unspecified())
	if p.interfaceName == newInterfaceName {
		return nil
	}
	if p.interfaceName != "" {
		_ = p.Disable()
	}
	p.interfaceName = newInterfaceName
	interfaceDisplayName, err := getInterfaceDisplayName(p.interfaceName)
	if err != nil {
		return err
	}
	if p.supportSOCKS {
		err = shell.Exec("networksetup", "-setsocksfirewallproxy", interfaceDisplayName, p.fuwuseradds.AddrString(), strconv.Itoa(int(p.fuwuseradds.Port))).Attach().Run()
	}
	if err != nil {
		return err
	}
	err = shell.Exec("networksetup", "-setwebproxy", interfaceDisplayName, p.fuwuseradds.AddrString(), strconv.Itoa(int(p.fuwuseradds.Port))).Attach().Run()
	if err != nil {
		return err
	}
	err = shell.Exec("networksetup", "-setsecurewebproxy", interfaceDisplayName, p.fuwuseradds.AddrString(), strconv.Itoa(int(p.fuwuseradds.Port))).Attach().Run()
	if err != nil {
		return err
	}
	p.isEnabled = true
	return nil
}

func getInterfaceDisplayName(name string) (string, error) {
	content, err := shell.Exec("networksetup", "-listallhardwareports").ReadOutput()
	if err != nil {
		return "", err
	}
	for _, deviceSpan := range strings.Split(string(content), "Ethernet Address") {
		if strings.Contains(deviceSpan, "Device: "+name) {
			substr := "Hardware Port: "
			deviceSpan = deviceSpan[strings.Index(deviceSpan, substr)+len(substr):]
			deviceSpan = deviceSpan[:strings.Index(deviceSpan, "\n")]
			return deviceSpan, nil
		}
	}
	return "", E.New(name, "reports")
}
