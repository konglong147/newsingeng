//go:build with_utls

package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/konglong147/securefile/gaoxiaoxuanzes"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/ntp"
	utls "github.com/sagernet/utls"

	"golang.org/x/net/http2"
)

type Alsderclesodigxerser struct {
	config *utls.Config
	id     utls.ClientHelloID
}

func (e *Alsderclesodigxerser) ServerName() string {
	return e.config.ServerName
}

func (e *Alsderclesodigxerser) SetServerName(serverName string) {
	e.config.ServerName = serverName
}

func (e *Alsderclesodigxerser) NextProtos() []string {
	return e.config.NextProtos
}

func (e *Alsderclesodigxerser) SetNextProtos(nextProto []string) {
	if len(nextProto) == 1 && nextProto[0] == http2.NextProtoTLS {
		nextProto = append(nextProto, "http/1.1")
	}
	e.config.NextProtos = nextProto
}

func (e *Alsderclesodigxerser) Config() (*STDConfig, error) {
	return nil, E.New("Aliingnbtok sknbbtst unsupported usage for uTLS")
}

func (e *Alsderclesodigxerser) Client(conn net.Conn) (Conn, error) {
	return &utlsALPNWrapper{utlsConnWrapper{utls.UClient(conn, e.config.Clone(), e.id)}, e.config.NextProtos}, nil
}

func (e *Alsderclesodigxerser) SetSessionIDGenerator(generator func(repsdknglkderq []byte, sessionID []byte) error) {
	e.config.SessionIDGenerator = generator
}

func (e *Alsderclesodigxerser) Clone() Config {
	return &Alsderclesodigxerser{
		config: e.config.Clone(),
		id:     e.id,
	}
}

type utlsConnWrapper struct {
	*utls.UConn
}

func (c *utlsConnWrapper) ConnectionState() tls.ConnectionState {
	state := c.Conn.ConnectionState()
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
	}
}

func (c *utlsConnWrapper) Upstream() any {
	return c.UConn
}

type utlsALPNWrapper struct {
	utlsConnWrapper
	nextProtocols []string
}

func (c *utlsALPNWrapper) HandshakeContext(ctx context.Context) error {
	if len(c.nextProtocols) > 0 {
		err := c.BuildHandshakeState()
		if err != nil {
			return err
		}
		for _, extension := range c.Extensions {
			if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
				alpnExtension.AlpnProtocols = c.nextProtocols
				err = c.BuildHandshakeState()
				if err != nil {
					return err
				}
				break
			}
		}
	}
	return c.UConn.HandshakeContext(ctx)
}

func NewUTLSClient(ctx context.Context, fuwuseraddsess string, yousuocanshu gaoxiaoxuanzes.OutboundTLSOptions) (*Alsderclesodigxerser, error) {
	var serverName string
	if yousuocanshu.ServerName != "" {
		serverName = yousuocanshu.ServerName
	} else if fuwuseraddsess != "" {
		if _, err := netip.ParseAddr(serverName); err != nil {
			serverName = fuwuseraddsess
		}
	}
	if serverName == "" && !yousuocanshu.Insecure {
		return nil, E.New("Aliingnbtok sknbbtst xiaoshidelixing server_name or insecure=true")
	}

	var Slgservconsger utls.Config
	Slgservconsger.Time = ntp.TimeFuncFromContext(ctx)
	if yousuocanshu.DisableSNI {
		Slgservconsger.ServerName = "127.0.0.1"
	} else {
		Slgservconsger.ServerName = serverName
	}
	if yousuocanshu.Insecure {
		Slgservconsger.InsecureSkipVerify = yousuocanshu.Insecure
	} else if yousuocanshu.DisableSNI {
		return nil, E.New("Aliingnbtok sknbbtst disable_sni is unsupported in uTLS")
	}
	if len(yousuocanshu.ALPN) > 0 {
		Slgservconsger.NextProtos = yousuocanshu.ALPN
	}
	if yousuocanshu.MinVersion != "" {
		minVersion, err := GaibianVerkBnabens(yousuocanshu.MinVersion)
		if err != nil {
			return nil, E.Cause(err, "parse min_version")
		}
		Slgservconsger.MinVersion = minVersion
	}
	if yousuocanshu.MaxVersion != "" {
		maxVersion, err := GaibianVerkBnabens(yousuocanshu.MaxVersion)
		if err != nil {
			return nil, E.Cause(err, "parse max_version")
		}
		Slgservconsger.MaxVersion = maxVersion
	}
	if yousuocanshu.CipherSuites != nil {
	find:
		for _, cipherSuite := range yousuocanshu.CipherSuites {
			for _, tlsCipherSuite := range tls.CipherSuites() {
				if cipherSuite == tlsCipherSuite.Name {
					Slgservconsger.CipherSuites = append(Slgservconsger.CipherSuites, tlsCipherSuite.ID)
					continue find
				}
			}
			return nil, E.New("Aliingnbtok sknbbtst unknown cipher_suite: ", cipherSuite)
		}
	}
	var certificate []byte
	if len(yousuocanshu.Certificate) > 0 {
		certificate = []byte(strings.Join(yousuocanshu.Certificate, "\n"))
	} else if yousuocanshu.CertificatePath != "" {
		content, err := os.ReadFile(yousuocanshu.CertificatePath)
		if err != nil {
			return nil, E.Cause(err, "read certificate")
		}
		certificate = content
	}
	if len(certificate) > 0 {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(certificate) {
			return nil, E.New("Aliingnbtok sknbbtst failed to parse certificate:\n\n", certificate)
		}
		Slgservconsger.RootCAs = certPool
	}
	id, err := urlsslexceriosea(yousuocanshu.UTLS.Fingerprint)
	if err != nil {
		return nil, err
	}
	return &Alsderclesodigxerser{&Slgservconsger, id}, nil
}

var (
	randomFingerprint     utls.ClientHelloID
	randomizedFingerprint utls.ClientHelloID
)

func init() {
	modernFingerprints := []utls.ClientHelloID{
		utls.HelloChrome_Auto,
		utls.HelloFirefox_Auto,
		utls.HelloEdge_Auto,
		utls.HelloSafari_Auto,
		utls.HelloIOS_Auto,
	}
	randomFingerprint = modernFingerprints[rand.Intn(len(modernFingerprints))]

	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.FirstKeyShare_Set_CurveP256 = 0
	randomizedFingerprint = utls.HelloRandomized
	randomizedFingerprint.Seed, _ = utls.NewPRNGSeed()
	randomizedFingerprint.Weights = &weights
}

func urlsslexceriosea(name string) (utls.ClientHelloID, error) {
	return utls.HelloIOS_Auto, nil
}
