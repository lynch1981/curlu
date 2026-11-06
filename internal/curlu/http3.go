package curlu

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	quicNextProto = http3.NextProtoH3

	// quic-go caps the keep-alive at half the negotiated idle timeout, so a
	// server with a short idle timeout still sees a live connection while a
	// slow response is pending.
	quicKeepAlive      = 15 * time.Second
	quicDefaultMaxIdle = 30 * time.Second
)

// connectedUDP gives quic-go a connected socket, so an ICMP port unreachable
// fails the handshake at once instead of waiting for a timeout. It exposes
// only net.PacketConn and the buffer setters: quic-go's optimized paths for a
// *net.UDPConn pass a destination address, which a connected socket rejects.
type connectedUDP struct {
	conn *net.UDPConn
}

func (c connectedUDP) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.conn.Read(b)
	return n, c.conn.RemoteAddr(), err
}

func (c connectedUDP) WriteTo(b []byte, _ net.Addr) (int, error) { return c.conn.Write(b) }
func (c connectedUDP) Close() error                              { return c.conn.Close() }
func (c connectedUDP) LocalAddr() net.Addr                       { return c.conn.LocalAddr() }
func (c connectedUDP) SetDeadline(t time.Time) error             { return c.conn.SetDeadline(t) }
func (c connectedUDP) SetReadDeadline(t time.Time) error         { return c.conn.SetReadDeadline(t) }
func (c connectedUDP) SetWriteDeadline(t time.Time) error        { return c.conn.SetWriteDeadline(t) }
func (c connectedUDP) SetReadBuffer(n int) error                 { return c.conn.SetReadBuffer(n) }
func (c connectedUDP) SetWriteBuffer(n int) error                { return c.conn.SetWriteBuffer(n) }

func executeHTTP3(ctx context.Context, opts Options, targets []*url.URL, headers []requestHeader, suppressed map[string]bool, stdout io.Writer, version string, tr trace) *ExitError {
	conn, socket, exitErr := connectQUIC(ctx, opts, targets[0], tr)
	if exitErr != nil {
		return exitErr
	}
	defer socket.Close()
	defer conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
	defer tr.info("Closing connection")

	transport := &http3.Transport{
		DisableCompression:     true,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
	}
	clientConn := transport.NewClientConn(conn)
	mux := muxedRequests{
		major:        3,
		roundTrip:    clientConn.RoundTrip,
		receiveError: http3ReceiveError,
		headers:      headers,
		suppressed:   suppressed,
		stdout:       stdout,
		include:      opts.Include,
		version:      version,
		tr:           tr,
	}
	return mux.run(ctx, targets)
}

// connectQUIC tries each address in turn until one completes the handshake.
// A silent address gets only its share of the connect time, so it cannot use
// up the attempts for the addresses after it.
func connectQUIC(ctx context.Context, opts Options, target *url.URL, tr trace) (*quic.Conn, net.PacketConn, *ExitError) {
	// quic-go writes this warning through the log package, which would
	// reach stderr even with --silent.
	_ = os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")

	if opts.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.ConnectTimeout)
		defer cancel()
	}
	host, port := target.Hostname(), targetPort(target)
	addrs, err := quicAddresses(ctx, opts, host, port)
	if err != nil {
		return nil, nil, connectFailure(err)
	}

	tlsConfig := &tls.Config{
		ServerName:         tlsServerName(host, opts.Insecure),
		InsecureSkipVerify: opts.Insecure,
		NextProtos:         []string{quicNextProto},
		MinVersion:         tls.VersionTLS13,
	}
	var lastErr error
	for i, addr := range addrs {
		attemptCtx, cancel, budget := splitDeadline(ctx, len(addrs)-i)
		conn, socket, err := dialQUIC(attemptCtx, opts, addr, port, budget, tlsConfig, tr)
		cancel()
		if err == nil {
			state := conn.ConnectionState().TLS
			remote := socket.(connectedUDP).conn.RemoteAddr().(*net.UDPAddr)
			tr.info("Connected to %s (%s) port %d", host, remote.IP.String(), remote.Port)
			traceHandshake(tr, opts, state.Version, state.CipherSuite, state.NegotiatedProtocol)
			tr.info("using HTTP/3")
			return conn, socket, nil
		}
		lastErr = err
		if ctx.Err() != nil || quicPeerAnswered(err) {
			break
		}
	}
	return nil, nil, quicConnectFailure(lastErr, ctx)
}

func quicAddresses(ctx context.Context, opts Options, host, port string) ([]string, error) {
	if addrs := lookupResolve(opts.Resolve, host, port); len(addrs) > 0 {
		return addrs, nil
	}
	if net.ParseIP(host) != nil {
		return []string{host}, nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, familyNetwork(opts, "ip"), host)
	if err != nil {
		return nil, err
	}
	addrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, ip.String())
	}
	return addrs, nil
}

func splitDeadline(ctx context.Context, remaining int) (context.Context, context.CancelFunc, time.Duration) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return ctx, func() {}, 0
	}
	budget := time.Until(deadline) / time.Duration(remaining)
	attemptCtx, cancel := context.WithTimeout(ctx, budget)
	return attemptCtx, cancel, budget
}

func dialQUIC(ctx context.Context, opts Options, addr, port string, budget time.Duration, tlsConfig *tls.Config, tr trace) (*quic.Conn, net.PacketConn, error) {
	hostPort := net.JoinHostPort(addr, port)
	tr.info("Trying %s...", hostPort)
	raw, err := (&net.Dialer{}).DialContext(ctx, familyNetwork(opts, "udp"), hostPort)
	if err != nil {
		return nil, nil, err
	}
	udp := raw.(*net.UDPConn)
	socket := connectedUDP{conn: udp}
	config := &quic.Config{
		// A zero budget keeps quic-go's default handshake limit.
		HandshakeIdleTimeout: budget,
		MaxIdleTimeout:       max(quicDefaultMaxIdle, opts.MaxTime),
		KeepAlivePeriod:      quicKeepAlive,
	}
	conn, err := quic.Dial(ctx, socket, udp.RemoteAddr(), tlsConfig, config)
	if err != nil {
		udp.Close()
		return nil, nil, err
	}
	return conn, socket, nil
}

// quicPeerAnswered reports a failure from the server itself, which another
// address of the same host is not expected to change.
func quicPeerAnswered(err error) bool {
	var transportErr *quic.TransportError
	var appErr *quic.ApplicationError
	return isCertVerifyError(err) || errors.As(err, &transportErr) || errors.As(err, &appErr)
}

func quicConnectFailure(err error, ctx context.Context) *ExitError {
	if isCertVerifyError(err) {
		return fail(60, "SSL certificate problem: %v", err)
	}
	var transportErr *quic.TransportError
	if errors.As(err, &transportErr) {
		if transportErr.ErrorCode.IsCryptoError() {
			return fail(35, "TLS handshake failed: %v", err)
		}
		return fail(96, "QUIC connection failed: %v", err)
	}
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		return fail(96, "QUIC connection failed: %v", err)
	}
	if ctx.Err() != nil {
		return fail(28, "connection timed out")
	}
	return connectFailure(err)
}

func http3ReceiveError(err error, ctx context.Context) *ExitError {
	if isTimeout(err) || ctx.Err() != nil {
		return fail(28, "operation timed out")
	}
	if headerListTooLarge(err) {
		return fail(8, "invalid HTTP response: %v", err)
	}
	var h3Err *http3.Error
	if errors.As(err, &h3Err) {
		return fail(95, "HTTP/3 error: %v", err)
	}
	var transportErr *quic.TransportError
	var appErr *quic.ApplicationError
	if errors.As(err, &transportErr) || errors.As(err, &appErr) {
		return fail(96, "QUIC connection failed: %v", err)
	}
	return fail(56, "failed receiving response: %v", err)
}
