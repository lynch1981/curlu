//go:build linux

package curlu

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

func startJA4TConn(ctx context.Context, dstIP net.IP, dstPort uint16, fp ja4tFingerprint) (net.Conn, error) {
	dstIP = rewriteLoopback(dstIP)
	srcIP, err := pickLocalIPv4(dstIP)
	if err != nil {
		return nil, err
	}
	srcPort, err := pickEphemeralPort(srcIP)
	if err != nil {
		return nil, err
	}
	raw, err := openRawPacketIO(srcIP, dstIP)
	if err != nil {
		return nil, err
	}
	conn, err := handshakeJA4T(ctx, raw, srcIP, dstIP.To4(), srcPort, dstPort, fp)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

// rewriteLoopback sends loopback destinations to the default gateway so a
// raw IP_HDRINCL SYN leaves the netns instead of hitting the ns loopback.
func rewriteLoopback(dst net.IP) net.IP {
	if dst == nil || !dst.IsLoopback() {
		return dst
	}
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return dst
	}
	gw, err := parseProcNetRouteGateway(data)
	if err != nil {
		return dst
	}
	return gw
}

func pickLocalIPv4(dst net.IP) (net.IP, error) {
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: dst, Port: 9})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	ip := c.LocalAddr().(*net.UDPAddr).IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("JA4T crafting is IPv4-only")
	}
	return ip, nil
}

func pickEphemeralPort(srcIP net.IP) (uint16, error) {
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: srcIP, Port: 0})
	if err != nil {
		return 0, err
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()
	return port, nil
}

type rawPacketIO struct {
	fd   int
	dst  unix.SockaddrInet4
	pkts chan []byte
	done chan struct{}
	once sync.Once
}

func openRawPacketIO(srcIP, dstIP net.IP) (*rawPacketIO, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("JA4T raw socket: %w (run via ./curl --ja4t as root)", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	var bind unix.SockaddrInet4
	copy(bind.Addr[:], srcIP.To4())
	if err := unix.Bind(fd, &bind); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	var dst unix.SockaddrInet4
	copy(dst.Addr[:], dstIP.To4())
	raw := &rawPacketIO{
		fd:   fd,
		dst:  dst,
		pkts: make(chan []byte, 16),
		done: make(chan struct{}),
	}
	go raw.readLoop()
	return raw, nil
}

func (r *rawPacketIO) readLoop() {
	defer close(r.pkts)
	buf := make([]byte, 65535)
	for {
		n, err := unix.Read(r.fd, buf)
		if err != nil {
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		select {
		case r.pkts <- pkt:
		case <-r.done:
			return
		}
	}
}

func (r *rawPacketIO) Write(b []byte) error {
	return unix.Sendto(r.fd, b, 0, &r.dst)
}

func (r *rawPacketIO) Read(ctx context.Context) ([]byte, error) {
	select {
	case pkt, ok := <-r.pkts:
		if !ok {
			return nil, net.ErrClosed
		}
		return pkt, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.done:
		return nil, net.ErrClosed
	}
}

func (r *rawPacketIO) Close() error {
	r.once.Do(func() {
		close(r.done)
		_ = unix.Close(r.fd)
	})
	return nil
}
