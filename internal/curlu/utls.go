package curlu

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// utlsHelloByName is the ClientHello catalog for this uTLS build. Keys are the
// exported uTLS constant names (HelloChrome_120), including Auto aliases.
// HelloCustom is omitted because it is an empty handshake, not a parrot.
var utlsHelloByName = map[string]utls.ClientHelloID{
	"HelloGolang":                      utls.HelloGolang,
	"HelloRandomized":                  utls.HelloRandomized,
	"HelloRandomizedALPN":              utls.HelloRandomizedALPN,
	"HelloRandomizedNoALPN":            utls.HelloRandomizedNoALPN,
	"HelloFirefox_Auto":                utls.HelloFirefox_Auto,
	"HelloFirefox_55":                  utls.HelloFirefox_55,
	"HelloFirefox_56":                  utls.HelloFirefox_56,
	"HelloFirefox_63":                  utls.HelloFirefox_63,
	"HelloFirefox_65":                  utls.HelloFirefox_65,
	"HelloFirefox_99":                  utls.HelloFirefox_99,
	"HelloFirefox_102":                 utls.HelloFirefox_102,
	"HelloFirefox_105":                 utls.HelloFirefox_105,
	"HelloFirefox_120":                 utls.HelloFirefox_120,
	"HelloChrome_Auto":                 utls.HelloChrome_Auto,
	"HelloChrome_58":                   utls.HelloChrome_58,
	"HelloChrome_62":                   utls.HelloChrome_62,
	"HelloChrome_70":                   utls.HelloChrome_70,
	"HelloChrome_72":                   utls.HelloChrome_72,
	"HelloChrome_83":                   utls.HelloChrome_83,
	"HelloChrome_87":                   utls.HelloChrome_87,
	"HelloChrome_96":                   utls.HelloChrome_96,
	"HelloChrome_100":                  utls.HelloChrome_100,
	"HelloChrome_102":                  utls.HelloChrome_102,
	"HelloChrome_106_Shuffle":          utls.HelloChrome_106_Shuffle,
	"HelloChrome_100_PSK":              utls.HelloChrome_100_PSK,
	"HelloChrome_112_PSK_Shuf":         utls.HelloChrome_112_PSK_Shuf,
	"HelloChrome_114_Padding_PSK_Shuf": utls.HelloChrome_114_Padding_PSK_Shuf,
	"HelloChrome_115_PQ":               utls.HelloChrome_115_PQ,
	"HelloChrome_115_PQ_PSK":           utls.HelloChrome_115_PQ_PSK,
	"HelloChrome_120":                  utls.HelloChrome_120,
	"HelloChrome_120_PQ":               utls.HelloChrome_120_PQ,
	"HelloChrome_131":                  utls.HelloChrome_131,
	"HelloChrome_133":                  utls.HelloChrome_133,
	"HelloIOS_Auto":                    utls.HelloIOS_Auto,
	"HelloIOS_11_1":                    utls.HelloIOS_11_1,
	"HelloIOS_12_1":                    utls.HelloIOS_12_1,
	"HelloIOS_13":                      utls.HelloIOS_13,
	"HelloIOS_14":                      utls.HelloIOS_14,
	"HelloAndroid_11_OkHttp":           utls.HelloAndroid_11_OkHttp,
	"HelloEdge_Auto":                   utls.HelloEdge_Auto,
	"HelloEdge_85":                     utls.HelloEdge_85,
	"HelloEdge_106":                    utls.HelloEdge_106,
	"HelloSafari_Auto":                 utls.HelloSafari_Auto,
	"HelloSafari_16_0":                 utls.HelloSafari_16_0,
	"Hello360_Auto":                    utls.Hello360_Auto,
	"Hello360_7_5":                     utls.Hello360_7_5,
	"Hello360_11_0":                    utls.Hello360_11_0,
	"HelloQQ_Auto":                     utls.HelloQQ_Auto,
	"HelloQQ_11_1":                     utls.HelloQQ_11_1,
}

func resolveUTLSHello(name string) (utls.ClientHelloID, string, bool) {
	if id, ok := utlsHelloByName[name]; ok {
		return id, name, true
	}
	for canonical, id := range utlsHelloByName {
		if strings.EqualFold(name, canonical) {
			return id, canonical, true
		}
	}
	return utls.ClientHelloID{}, "", false
}

func utlsHelloNames() []string {
	names := make([]string, 0, len(utlsHelloByName))
	for name := range utlsHelloByName {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func handshakeUTLS(conn net.Conn, opts Options, serverName string, stderr io.Writer, ctx context.Context, tr trace) (net.Conn, string, *ExitError) {
	helloID := utls.HelloGolang
	if opts.UTLSHello.Client != "" {
		helloID = opts.UTLSHello
	}
	config := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // Deliberate curlu v1 policy.
	}
	if helloID == utls.HelloGolang {
		config.NextProtos = golangNextProtos(opts)
	}
	tlsConn := utls.UClient(conn, config, helloID)

	if utlsMutatesHello(opts) {
		if err := tlsConn.BuildHandshakeState(); err != nil {
			return nil, "", fail(35, "TLS handshake failed: %v", err)
		}
		tlsConn.HandshakeState.Hello.CipherSuites = append(tlsConn.HandshakeState.Hello.CipherSuites, opts.UTLSCiphers...)
		if helloID != utls.HelloGolang {
			applyParrotALPN(tlsConn, opts)
		}
		if opts.UTLSInfo {
			_, _ = fmt.Fprintf(stderr, "EXPECTED_CIPHER_COUNT=%d\n", countNonGREASE(tlsConn.HandshakeState.Hello.CipherSuites))
		}
		if helloID != utls.HelloGolang {
			if err := tlsConn.MarshalClientHello(); err != nil {
				return nil, "", fail(35, "TLS handshake failed: %v", err)
			}
		}
	}

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		if isTimeout(err) || ctx.Err() != nil {
			return nil, "", fail(28, "connection timed out")
		}
		return nil, "", fail(35, "TLS handshake failed: %v", err)
	}
	state := tlsConn.ConnectionState()
	tr.info("SSL connection using %s / %s", tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite))
	if state.NegotiatedProtocol != "" {
		tr.info("ALPN: server accepted %s", state.NegotiatedProtocol)
	}
	tr.info("SSL certificate verification is disabled")
	switch state.NegotiatedProtocol {
	case "", "http/1.1", "h2":
		return tlsConn, state.NegotiatedProtocol, nil
	default:
		return nil, state.NegotiatedProtocol, fail(1, "server negotiated protocol %q; only HTTP/1.1 and HTTP/2 are supported", state.NegotiatedProtocol)
	}
}

func utlsOptionsSet(opts Options) bool {
	return opts.UTLSHello.Client != "" || len(opts.UTLSCiphers) > 0 || opts.UTLSInfo || opts.UTLSALPNNone || opts.UTLSALPN != ""
}

func utlsMutatesHello(opts Options) bool {
	return len(opts.UTLSCiphers) > 0 || opts.UTLSInfo || opts.UTLSALPNNone || opts.UTLSALPN != ""
}

func golangNextProtos(opts Options) []string {
	switch {
	case opts.UTLSALPNNone:
		return nil
	case opts.UTLSALPN != "":
		return []string{opts.UTLSALPN, "http/1.1"}
	default:
		return []string{"http/1.1"}
	}
}

func applyParrotALPN(tlsConn *utls.UConn, opts Options) {
	if !opts.UTLSALPNNone && opts.UTLSALPN == "" {
		return
	}
	if opts.UTLSALPNNone {
		keep := make([]utls.TLSExtension, 0, len(tlsConn.Extensions))
		for _, ext := range tlsConn.Extensions {
			if _, ok := ext.(*utls.ALPNExtension); ok {
				continue
			}
			keep = append(keep, ext)
		}
		tlsConn.Extensions = keep
		tlsConn.HandshakeState.Hello.AlpnProtocols = nil
		return
	}
	first := opts.UTLSALPN
	for _, ext := range tlsConn.Extensions {
		alpn, ok := ext.(*utls.ALPNExtension)
		if !ok {
			continue
		}
		alpn.AlpnProtocols = replaceFirstALPN(alpn.AlpnProtocols, first)
		tlsConn.HandshakeState.Hello.AlpnProtocols = alpn.AlpnProtocols
		return
	}
	alpn := &utls.ALPNExtension{AlpnProtocols: []string{first}}
	tlsConn.Extensions = append(tlsConn.Extensions, alpn)
	tlsConn.HandshakeState.Hello.AlpnProtocols = alpn.AlpnProtocols
}

func replaceFirstALPN(existing []string, first string) []string {
	out := []string{first}
	if len(existing) > 1 {
		out = append(out, existing[1:]...)
	}
	return out
}

func countNonGREASE(ciphers []uint16) int {
	count := 0
	for _, cipher := range ciphers {
		if !isGREASE(cipher) {
			count++
		}
	}
	return count
}

func isGREASE(value uint16) bool {
	high, low := byte(value>>8), byte(value)
	return high == low && low&0x0f == 0x0a
}
