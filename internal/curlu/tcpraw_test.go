package curlu

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
)

type pipeIO struct {
	recv <-chan []byte
	send chan<- []byte
	done chan struct{}
}

func newPacketPipe() (*pipeIO, *pipeIO) {
	ab := make(chan []byte, 16)
	ba := make(chan []byte, 16)
	done := make(chan struct{})
	return &pipeIO{recv: ba, send: ab, done: done}, &pipeIO{recv: ab, send: ba, done: done}
}

func (p *pipeIO) Write(b []byte) error {
	pkt := append([]byte(nil), b...)
	select {
	case p.send <- pkt:
		return nil
	case <-p.done:
		return net.ErrClosed
	}
}

func (p *pipeIO) Read(ctx context.Context) ([]byte, error) {
	select {
	case pkt, ok := <-p.recv:
		if !ok {
			return nil, io.EOF
		}
		return pkt, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.done:
		return nil, net.ErrClosed
	}
}

func (p *pipeIO) Close() error {
	select {
	case <-p.done:
	default:
		close(p.done)
	}
	return nil
}

func TestJA4THandshakeAndHTTP(t *testing.T) {
	clientIO, serverIO := newPacketPipe()
	src := net.IPv4(10, 0, 0, 1).To4()
	dst := net.IPv4(10, 0, 0, 2).To4()
	fp, err := parseJA4T("64240_2-4-8-1-3_1460_7")
	if err != nil {
		t.Fatal(err)
	}

	var sawGET bytes.Buffer
	errCh := make(chan error, 1)
	go func() {
		errCh <- servePipeHTTP(serverIO, dst, src, 80, fp, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", &sawGET)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := handshakeJA4T(ctx, clientIO, src, dst, 12345, 80, fp, nil)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	req := []byte("GET /health HTTP/1.1\r\nHost: example\r\n\r\n")
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if _, err := io.Copy(&got, conn); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if got.String() != "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" {
		t.Fatalf("response %q", got.String())
	}
	if !bytes.Contains(sawGET.Bytes(), req) {
		t.Fatalf("server saw %q", sawGET.Bytes())
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestJA4TRetransmitSchedule(t *testing.T) {
	clientIO, serverIO := newPacketPipe()
	src := net.IPv4(10, 0, 0, 1).To4()
	dst := net.IPv4(10, 0, 0, 2).To4()
	fp, err := parseJA4T("8192_00_00_00")
	if err != nil {
		t.Fatal(err)
	}

	var afterChans []chan time.Time
	var mu sync.Mutex
	ready := make(chan struct{}, 8)
	ja4tAfter = func(time.Duration) <-chan time.Time {
		ch := make(chan time.Time, 1)
		mu.Lock()
		afterChans = append(afterChans, ch)
		mu.Unlock()
		ready <- struct{}{}
		return ch
	}
	t.Cleanup(func() { ja4tAfter = time.After })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		_, err := handshakeJA4T(ctx, clientIO, src, dst, 12345, 80, fp, []time.Duration{time.Second, 2 * time.Second})
		errCh <- err
	}()

	synCount := 0
	waitSYN := func() {
		t.Helper()
		raw, err := serverIO.Read(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		_, tcp, _, err := parseIPv4TCP(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !tcp.SYN || tcp.ACK {
			t.Fatalf("expected SYN, got SYN=%v ACK=%v", tcp.SYN, tcp.ACK)
		}
		synCount++
	}
	waitSYN()
	<-ready
	afterChans[0] <- time.Time{}
	waitSYN()
	<-ready
	afterChans[1] <- time.Time{}
	waitSYN()
	if synCount != 3 {
		t.Fatalf("syn count %d", synCount)
	}
	cancel()
	if err := <-errCh; err == nil {
		t.Fatal("expected handshake error")
	}
}

func TestJA4TExecuteHTTP(t *testing.T) {
	original := startJA4T
	t.Cleanup(func() { startJA4T = original })
	startJA4T = func(context.Context, net.IP, uint16, ja4tFingerprint, []time.Duration) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			var req []byte
			buf := make([]byte, 256)
			for {
				n, err := server.Read(buf)
				if n > 0 {
					req = append(req, buf[:n]...)
				}
				if bytes.Contains(req, []byte("\r\n\r\n")) || err != nil {
					break
				}
			}
			_, _ = server.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
		}()
		return client, nil
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-sS", "--ja4t", "8192_00_00_00", "http://127.0.0.1:9/health"}, &stdout, &stderr, "test")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.String() != "ok" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestJA4TExecuteRejectedOnIPv6(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--ja4t", "8192_00_00_00", "http://[::1]/"}, &stdout, &stderr, "test")
	if code != 2 {
		t.Fatalf("literal: code = %d, stderr = %q", code, stderr.String())
	}
	code = Run([]string{
		"--ja4t", "8192_00_00_00",
		"--resolve", "example.test:80:[::1]",
		"http://example.test/",
	}, &stdout, &stderr, "test")
	if code != 2 {
		t.Fatalf("resolve: code = %d, stderr = %q", code, stderr.String())
	}
}

func TestParseProcNetRouteGateway(t *testing.T) {
	data := []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0100A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
		"eth0\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n")
	ip, err := parseProcNetRouteGateway(data)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.IPv4(192, 168, 0, 1)) {
		t.Fatalf("gateway = %v", ip)
	}
}

func TestJA4TExecuteRejectedOnHTTPS(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--ja4t", "64240_2-4-8-1-3_1460_7", "https://example.test/"}, &stdout, &stderr, "test")
	if code != 2 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
}

func TestJA4TExecuteRejectedWithUTLS(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--ja4t", "64240_2-4-8-1-3_1460_7", "--utls-info", "http://example.test/"}, &stdout, &stderr, "test")
	if code != 2 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
}

func servePipeHTTP(io *pipeIO, srcIP, dstIP net.IP, srcPort uint16, clientFP ja4tFingerprint, response string, received *bytes.Buffer) error {
	ctx := context.Background()
	iss := uint32(1000)
	var rcvNxt uint32
	var dstPort uint16
	var tsEcho uint32
	useTS := fingerprintHasKind(clientFP, 8)
	for {
		raw, err := io.Read(ctx)
		if err != nil {
			return err
		}
		ip, tcp, payload, err := parseIPv4TCP(raw)
		if err != nil {
			continue
		}
		if !ip.DstIP.Equal(srcIP) {
			continue
		}
		if echo := timestampEcho(tcp); echo != 0 {
			tsEcho = echo
		}
		if tcp.SYN && !tcp.ACK {
			rcvNxt = tcp.Seq + 1
			dstPort = uint16(tcp.SrcPort)
			pkt, err := serverSegment(srcIP, dstIP, srcPort, dstPort, iss, rcvNxt, true, true, false, false, useTS, tsEcho, nil)
			if err != nil {
				return err
			}
			if err := io.Write(pkt); err != nil {
				return err
			}
			continue
		}
		if len(payload) > 0 {
			received.Write(payload)
			rcvNxt += uint32(len(payload))
			if bytes.Contains(received.Bytes(), []byte("\r\n\r\n")) {
				ack, err := serverSegment(srcIP, dstIP, srcPort, dstPort, iss+1, rcvNxt, false, true, false, false, useTS, tsEcho, nil)
				if err != nil {
					return err
				}
				if err := io.Write(ack); err != nil {
					return err
				}
				body := []byte(response)
				data, err := serverSegment(srcIP, dstIP, srcPort, dstPort, iss+1, rcvNxt, false, true, true, false, useTS, tsEcho, body)
				if err != nil {
					return err
				}
				if err := io.Write(data); err != nil {
					return err
				}
				fin, err := serverSegment(srcIP, dstIP, srcPort, dstPort, iss+1+uint32(len(body)), rcvNxt, false, true, false, true, useTS, tsEcho, nil)
				if err != nil {
					return err
				}
				return io.Write(fin)
			}
		}
	}
}

func serverSegment(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, syn, ackFlag, psh, fin, useTS bool, tsEcho uint32, payload []byte) ([]byte, error) {
	var options []layers.TCPOption
	if syn {
		var mss [2]byte
		binary.BigEndian.PutUint16(mss[:], 1460)
		options = append(options, layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionData: mss[:]})
		if useTS {
			var ts [8]byte
			binary.BigEndian.PutUint32(ts[:4], 0x11111111)
			binary.BigEndian.PutUint32(ts[4:], tsEcho)
			options = append(options,
				layers.TCPOption{OptionType: layers.TCPOptionKindNop},
				layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionData: ts[:]},
			)
		}
	} else if useTS {
		options = dataOptions(true, tsEcho)
	}
	return serializeSegment(srcIP, dstIP, srcPort, dstPort, seq, ack, 65535, 1, syn, ackFlag, psh, fin, options, payload)
}
