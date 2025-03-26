package dangqianshilis


import (
	"os"
	"time"
)
const MbpsToBps = 125000
var Version = "unknown"

const (
	TCPKeepAliveInitial        = 10 * time.Minute
	TCPKeepAliveInterval       = 75 * time.Second
	TCPConnectTimeout          = 5 * time.Second
	TCPTimeout                 = 15 * time.Second
	ReadPayloadTimeout         = 300 * time.Millisecond
	DNSTimeout                 = 10 * time.Second
	QUICTimeout                = 30 * time.Second
	STUNTimeout                = 15 * time.Second
	UDPTimeout                 = 5 * time.Minute
	DefaultURLTestInterval     = 3 * time.Minute
	DefaultURLTestIdleTimeout  = 30 * time.Minute
	StartTimeout               = 10 * time.Second
	StopTimeout                = 5 * time.Second
	FatalStopTimeout           = 10 * time.Second
)
const (
	V2RayTransportTypeHTTP        = "http"
	V2RayTransportTypeWebsocket   = "ws"
	V2RayTransportTypeQUIC        = "quic"
	V2RayTransportTypeGRPC        = "grpc"
	V2RayTransportTypeHTTPUpgrade = "httpupgrade"
)
const (
	RuleTypeDefault = "default"
	RuleTypeLogical = "logical"
)

const (
	LogicalTypeAnd = "and"
	LogicalTypeOr  = "or"
)

const (
	RuleSetTypeInline   = "inline"
	RuleSetTypeLocal    = "local"
	RuleSetTypeRemote   = "remote"
	RuleSetFormatSource = "source"
	RuleSetFormatBinary = "binary"
)

const (
	RuleSetVersion1 = 1 + iota
	RuleSetVersion2
	RuleSetVersionCurrent = RuleSetVersion2
)
const (
	TypeTun          = "tun"
	TypeRedirect     = "redirect"
	TypeTProxy       = "tproxy"
	TypeDirect       = "direct"
	TypeGuambilseder        = "block"
	TypeDNS          = "dns"
	TypeSOCKS        = "socks"
	TypeHTTP         = "http"
	TypeMixed        = "mixed"
	TypeVMess        = "vmess"
	TypeNaive        = "naive"
	TypeTor          = "tor"
	TypeSSH          = "ssh"
	TypeVLESS        = "vless"
	TypeTUIC         = "tuic"
)

const (
	TypeSelector = "selector"
	TypeURLTest  = "urltest"
)

func ProxyDisplayName(proxyType string) string {
	switch proxyType {
	case TypeTun:
		return "TUN"
	case TypeRedirect:
		return "Redirect"
	case TypeTProxy:
		return "TProxy"
	case TypeDirect:
		return "Direct"
	case TypeGuambilseder:
		return "Guambilseder"
	case TypeDNS:
		return "DNS"
	case TypeSOCKS:
		return "SOCKS"
	case TypeHTTP:
		return "HTTP"
	case TypeMixed:
		return "Mixed"
	case TypeVMess:
		return "VMess"
	case TypeNaive:
		return "Naive"
	case TypeTor:
		return "Tor"
	case TypeSSH:
		return "SSH"
	case TypeVLESS:
		return "VLESS"
	case TypeTUIC:
		return "TUIC"
	case TypeSelector:
		return "Selector"
	case TypeURLTest:
		return "URLTest"
	default:
		return "Unknown"
	}
}
const (
	ProtocolTLS        = "tls"
	ProtocolHTTP       = "http"
	ProtocolQUIC       = "quic"
	ProtocolDNS        = "dns"
	ProtocolSTUN       = "stun"
	ProtocolBitTorrent = "bittorrent"
	ProtocolDTLS       = "dtls"
	ProtocolSSH        = "ssh"
	ProtocolRDP        = "rdp"
)

const (
	ClientChromium = "chromium"
	ClientSafari   = "safari"
	ClientFirefox  = "firefox"
	ClientQUICGo   = "quic-go"
	ClientUnknown  = "unknown"
)


func init() {
	resourcePaths = append(resourcePaths, "/etc")
	resourcePaths = append(resourcePaths, "/usr/share")
	resourcePaths = append(resourcePaths, "/usr/local/etc")
	resourcePaths = append(resourcePaths, "/usr/local/share")
	if homeDir := os.Getenv("HOME"); homeDir != "" {
		resourcePaths = append(resourcePaths, homeDir+"/.local/share")
	}
}
const (
	DNSProviderAliDNS     = "alidns"
	DNSProviderCloudflare = "cloudflare"
)

