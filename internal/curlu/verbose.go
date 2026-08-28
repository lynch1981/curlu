package curlu

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

type trace struct {
	w  io.Writer
	on bool
}

func newTrace(w io.Writer, on bool) trace {
	return trace{w: w, on: on}
}

func (t trace) info(format string, args ...any) {
	if !t.on {
		return
	}
	_, _ = fmt.Fprintf(t.w, "* "+format+"\n", args...)
}

func (t trace) dump(prefix string, block []byte) {
	if !t.on {
		return
	}
	text := strings.TrimSuffix(string(block), "\n")
	text = strings.TrimSuffix(text, "\r")
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSuffix(line, "\r")
		_, _ = fmt.Fprintf(t.w, "%s%s\n", prefix, line)
	}
}

func (t trace) connected(host string, conn net.Conn) {
	addr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		t.info("Connected to %s (%s)", host, conn.RemoteAddr().String())
		return
	}
	t.info("Trying %s...", net.JoinHostPort(addr.IP.String(), strconv.Itoa(addr.Port)))
	t.info("Connected to %s (%s) port %d", host, addr.IP.String(), addr.Port)
}
