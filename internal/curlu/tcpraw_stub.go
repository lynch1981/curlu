//go:build !linux

package curlu

import (
	"context"
	"fmt"
	"net"
	"time"
)

func startJA4TConn(context.Context, net.IP, uint16, ja4tFingerprint, []time.Duration) (net.Conn, error) {
	return nil, fmt.Errorf("JA4T crafting is Linux-only")
}
