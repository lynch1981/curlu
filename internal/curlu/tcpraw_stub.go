//go:build !linux

package curlu

import (
	"context"
	"fmt"
	"net"
)

func startJA4TConn(context.Context, net.IP, uint16, ja4tFingerprint) (net.Conn, error) {
	return nil, fmt.Errorf("JA4T crafting is Linux-only")
}
