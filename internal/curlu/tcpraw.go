package curlu

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var (
	ja4tNow         = time.Now
	startJA4T       = startJA4TConn
	errJA4TIPv4Only = errors.New("JA4T crafting is IPv4-only")
)

func lookupIPv4(ctx context.Context, host string) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return nil, errJA4TIPv4Only
		}
		return []string{ip.To4().String()}, nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	addrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip.To4() != nil {
			addrs = append(addrs, ip.To4().String())
		}
	}
	if len(addrs) == 0 {
		return nil, errJA4TIPv4Only
	}
	return addrs, nil
}

func dialJA4TAddrs(ctx context.Context, addrs []string, port string, fp ja4tFingerprint) (net.Conn, error) {
	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}
	var lastErr error
	sawV4 := false
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() == nil {
			continue
		}
		sawV4 = true
		conn, err := startJA4T(ctx, ip.To4(), uint16(portNum), fp)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, err
		}
	}
	if !sawV4 {
		return nil, errJA4TIPv4Only
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no addresses")
	}
	return nil, lastErr
}

type packetIO interface {
	Write([]byte) error
	Read(context.Context) ([]byte, error)
	Close() error
}

type tcpSegment struct {
	tcp     *layers.TCP
	payload []byte
}

type ja4tConn struct {
	io      packetIO
	srcIP   net.IP
	dstIP   net.IP
	srcPort uint16
	dstPort uint16
	window  uint16
	peerMSS uint16
	useTS   bool
	packets chan tcpSegment

	mu            sync.Mutex
	cond          *sync.Cond
	sndNxt        uint32
	rcvNxt        uint32
	tsEcho        uint32
	ipID          uint16
	readBuf       []byte
	readDeadline  time.Time
	writeDeadline time.Time
	closed        bool
	gotFIN        bool
	err           error
	stop          context.CancelFunc
}

func handshakeJA4T(ctx context.Context, io packetIO, srcIP, dstIP net.IP, srcPort, dstPort uint16, fp ja4tFingerprint) (*ja4tConn, error) {
	iss, err := randomSeq()
	if err != nil {
		return nil, err
	}
	useTS := fingerprintHasKind(fp, 8)
	options, err := fp.tcpOptions(uint32(ja4tNow().UnixMilli()))
	if err != nil {
		return nil, err
	}
	syn, err := serializeSegment(srcIP, dstIP, srcPort, dstPort, iss, 0, fp.Window, 1, true, false, false, false, options, nil)
	if err != nil {
		return nil, err
	}
	if err := io.Write(syn); err != nil {
		return nil, err
	}

	loopCtx, stop := context.WithCancel(context.Background())
	conn := &ja4tConn{
		io:      io,
		srcIP:   srcIP,
		dstIP:   dstIP,
		srcPort: srcPort,
		dstPort: dstPort,
		window:  fp.Window,
		useTS:   useTS,
		packets: make(chan tcpSegment, 32),
		stop:    stop,
	}
	conn.cond = sync.NewCond(&conn.mu)
	go conn.pump(loopCtx)

	synack, err := conn.waitSYNACK(ctx, iss)
	if err != nil {
		stop()
		return nil, err
	}
	conn.rcvNxt = synack.Seq + 1
	conn.tsEcho = timestampEcho(synack)
	conn.peerMSS = synackMSS(synack)
	conn.sndNxt = iss + 1
	ackPkt, err := serializeSegment(srcIP, dstIP, srcPort, dstPort, conn.sndNxt, conn.rcvNxt, fp.Window, 1, false, true, false, false, dataOptions(useTS, conn.tsEcho), nil)
	if err != nil {
		stop()
		return nil, err
	}
	if err := io.Write(ackPkt); err != nil {
		stop()
		return nil, err
	}
	go conn.recvLoop()
	return conn, nil
}

func (c *ja4tConn) pump(ctx context.Context) {
	defer close(c.packets)
	for {
		raw, err := c.io.Read(ctx)
		if err != nil {
			if ctx.Err() == nil {
				c.fail(err)
			}
			return
		}
		ip, tcp, payload, err := parseIPv4TCP(raw)
		if err != nil || !matchReply(ip, tcp, c.srcIP, c.dstIP, c.srcPort, c.dstPort) {
			continue
		}
		if tcp.RST {
			c.fail(errors.New("connection reset"))
			return
		}
		select {
		case c.packets <- tcpSegment{tcp: tcp, payload: payload}:
		case <-ctx.Done():
			return
		}
	}
}

func (c *ja4tConn) waitSYNACK(ctx context.Context, iss uint32) (*layers.TCP, error) {
	for {
		select {
		case seg, ok := <-c.packets:
			if !ok {
				if err := c.currentErr(); err != nil {
					return nil, err
				}
				return nil, net.ErrClosed
			}
			if seg.tcp.SYN && seg.tcp.ACK && seg.tcp.Ack == iss+1 {
				return seg.tcp, nil
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (c *ja4tConn) recvLoop() {
	for seg := range c.packets {
		c.handleSegment(seg.tcp, seg.payload)
	}
}

func (c *ja4tConn) handleSegment(tcp *layers.TCP, payload []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if echo := timestampEcho(tcp); echo != 0 {
		c.tsEcho = echo
	}
	if tcp.Seq != c.rcvNxt {
		_ = c.sendLocked(false, true, false, false, nil)
		return
	}
	if len(payload) > 0 {
		c.readBuf = append(c.readBuf, payload...)
		c.rcvNxt += uint32(len(payload))
		_ = c.sendLocked(false, true, false, false, nil)
		c.cond.Broadcast()
	}
	if tcp.FIN {
		c.rcvNxt++
		c.gotFIN = true
		_ = c.sendLocked(false, true, false, false, nil)
		c.cond.Broadcast()
	}
}

func (c *ja4tConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.readBuf) == 0 && c.err == nil && !c.gotFIN && !c.closed {
		if err := waitDeadline(c.cond, c.readDeadline); err != nil {
			return 0, err
		}
	}
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	if c.err != nil {
		return 0, c.err
	}
	return 0, io.EOF
}

func (c *ja4tConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return 0, c.err
	}
	if c.closed {
		return 0, net.ErrClosed
	}
	if err := deadlineErr(c.writeDeadline); err != nil {
		return 0, err
	}
	// Fire-and-forget: lost data is not retransmitted.
	sent := 0
	mss := int(c.peerMSS)
	if mss <= 0 {
		mss = 1460
	}
	for sent < len(p) {
		end := sent + mss
		if end > len(p) {
			end = len(p)
		}
		chunk := p[sent:end]
		if err := c.sendLocked(false, true, true, false, chunk); err != nil {
			return sent, err
		}
		c.sndNxt += uint32(len(chunk))
		sent = end
	}
	return sent, nil
}

func (c *ja4tConn) Close() error {
	c.mu.Lock()
	if !c.closed && c.err == nil {
		_ = c.sendLocked(false, true, false, true, nil)
		c.sndNxt++
	}
	c.closed = true
	c.cond.Broadcast()
	stop := c.stop
	c.mu.Unlock()
	if stop != nil {
		stop()
	}
	return c.io.Close()
}

func (c *ja4tConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: append(net.IP(nil), c.srcIP...), Port: int(c.srcPort)}
}

func (c *ja4tConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: append(net.IP(nil), c.dstIP...), Port: int(c.dstPort)}
}

func (c *ja4tConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}

func (c *ja4tConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}

func (c *ja4tConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *ja4tConn) fail(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == nil {
		c.err = err
	}
	if c.cond != nil {
		c.cond.Broadcast()
	}
}

func (c *ja4tConn) currentErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *ja4tConn) sendLocked(syn, ack, psh, fin bool, payload []byte) error {
	c.ipID++
	pkt, err := serializeSegment(c.srcIP, c.dstIP, c.srcPort, c.dstPort, c.sndNxt, c.rcvNxt, c.window, c.ipID, syn, ack, psh, fin, dataOptions(c.useTS, c.tsEcho), payload)
	if err != nil {
		return err
	}
	return c.io.Write(pkt)
}

func dataOptions(useTS bool, tsEcho uint32) []layers.TCPOption {
	if !useTS {
		return nil
	}
	var data [8]byte
	binary.BigEndian.PutUint32(data[:4], uint32(ja4tNow().UnixMilli()))
	binary.BigEndian.PutUint32(data[4:], tsEcho)
	return []layers.TCPOption{
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindTimestamps, OptionData: data[:]},
	}
}

func serializeSegment(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, window uint16, id uint16, syn, ackFlag, psh, fin bool, options []layers.TCPOption, payload []byte) ([]byte, error) {
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Id:       id,
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		Ack:     ack,
		SYN:     syn,
		ACK:     ackFlag,
		PSH:     psh,
		FIN:     fin,
		Window:  window,
		Options: options,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	layersToSend := []gopacket.SerializableLayer{ip, tcp}
	if len(payload) > 0 {
		layersToSend = append(layersToSend, gopacket.Payload(payload))
	}
	if err := gopacket.SerializeLayers(buf, opts, layersToSend...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parseIPv4TCP(raw []byte) (*layers.IPv4, *layers.TCP, []byte, error) {
	packet := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if ipLayer == nil || tcpLayer == nil {
		return nil, nil, nil, fmt.Errorf("not IPv4 TCP")
	}
	ip := ipLayer.(*layers.IPv4)
	tcp := tcpLayer.(*layers.TCP)
	return ip, tcp, tcp.Payload, nil
}

func matchReply(ip *layers.IPv4, tcp *layers.TCP, srcIP, dstIP net.IP, srcPort, dstPort uint16) bool {
	return ip.SrcIP.Equal(dstIP) && ip.DstIP.Equal(srcIP) && uint16(tcp.SrcPort) == dstPort && uint16(tcp.DstPort) == srcPort
}

func synackMSS(tcp *layers.TCP) uint16 {
	for _, option := range tcp.Options {
		if option.OptionType == layers.TCPOptionKindMSS && len(option.OptionData) >= 2 {
			return binary.BigEndian.Uint16(option.OptionData)
		}
	}
	return 1460
}

func timestampEcho(tcp *layers.TCP) uint32 {
	for _, option := range tcp.Options {
		if option.OptionType == layers.TCPOptionKindTimestamps && len(option.OptionData) >= 4 {
			return binary.BigEndian.Uint32(option.OptionData[:4])
		}
	}
	return 0
}

func randomSeq() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

func waitDeadline(cond *sync.Cond, deadline time.Time) error {
	if err := deadlineErr(deadline); err != nil {
		return err
	}
	if deadline.IsZero() {
		cond.Wait()
		return nil
	}
	timer := time.AfterFunc(time.Until(deadline), func() { cond.Broadcast() })
	cond.Wait()
	timer.Stop()
	return deadlineErr(deadline)
}

func deadlineErr(deadline time.Time) error {
	if !deadline.IsZero() && !ja4tNow().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	return nil
}

func parseProcNetRouteGateway(data []byte) (net.IP, error) {
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		raw, err := strconv.ParseUint(fields[2], 16, 32)
		if err != nil {
			return nil, err
		}
		ip := net.IPv4(byte(raw), byte(raw>>8), byte(raw>>16), byte(raw>>24)).To4()
		if ip == nil || ip.IsUnspecified() {
			continue
		}
		return ip, nil
	}
	return nil, fmt.Errorf("no default IPv4 gateway")
}
