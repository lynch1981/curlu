package curlu

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gopacket/gopacket/layers"
)

type ja4tFingerprint struct {
	Window uint16
	Kinds  []uint8
	MSS    uint16
	Scale  uint8
}

func ja4tEnabled(opts Options) bool {
	return opts.JA4T != nil
}

func parseJA4T(value string) (ja4tFingerprint, error) {
	parts := strings.Split(value, "_")
	if len(parts) != 4 {
		return ja4tFingerprint{}, fmt.Errorf("invalid JA4T %q (expected window_options_mss_wscale)", value)
	}
	window, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return ja4tFingerprint{}, fmt.Errorf("invalid JA4T window %q", parts[0])
	}
	kinds, err := parseJA4TKinds(parts[1])
	if err != nil {
		return ja4tFingerprint{}, err
	}
	mss, err := parseJA4TSection(parts[2], 16, "MSS")
	if err != nil {
		return ja4tFingerprint{}, err
	}
	scale, err := parseJA4TSection(parts[3], 8, "window scale")
	if err != nil {
		return ja4tFingerprint{}, err
	}
	fp := ja4tFingerprint{Window: uint16(window), Kinds: kinds, MSS: uint16(mss), Scale: uint8(scale)}
	if err := fp.validate(); err != nil {
		return ja4tFingerprint{}, err
	}
	return fp, nil
}

func parseJA4TKinds(value string) ([]uint8, error) {
	if value == "00" || value == "" {
		return nil, nil
	}
	fields := strings.Split(value, "-")
	kinds := make([]uint8, 0, len(fields))
	for _, field := range fields {
		n, err := strconv.ParseUint(field, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid JA4T option kind %q", field)
		}
		kinds = append(kinds, uint8(n))
	}
	return kinds, nil
}

func parseJA4TSection(value string, bits int, name string) (uint64, error) {
	if value == "00" {
		return 0, nil
	}
	n, err := strconv.ParseUint(value, 10, bits)
	if err != nil {
		return 0, fmt.Errorf("invalid JA4T %s %q", name, value)
	}
	return n, nil
}

func (fp ja4tFingerprint) validate() error {
	hasMSS, hasScale := false, false
	for _, kind := range fp.Kinds {
		switch kind {
		case 0, 1, 4:
		case 2:
			hasMSS = true
		case 3:
			hasScale = true
		case 8:
		default:
			return fmt.Errorf("unsupported TCP option kind %d", kind)
		}
	}
	if hasMSS && fp.MSS == 0 {
		return fmt.Errorf("JA4T option kind 2 requires an MSS value")
	}
	if !hasMSS && fp.MSS != 0 {
		return fmt.Errorf("JA4T MSS is set but option kind 2 is missing")
	}
	if !hasScale && fp.Scale != 0 {
		return fmt.Errorf("JA4T window scale is set but option kind 3 is missing")
	}
	if _, err := fp.tcpOptions(0); err != nil {
		return err
	}
	return nil
}

func (fp ja4tFingerprint) String() string {
	opts := "00"
	if len(fp.Kinds) > 0 {
		parts := make([]string, len(fp.Kinds))
		for i, kind := range fp.Kinds {
			parts[i] = strconv.FormatUint(uint64(kind), 10)
		}
		opts = strings.Join(parts, "-")
	}
	mss := "00"
	if fp.MSS != 0 {
		mss = fmt.Sprintf("%02d", fp.MSS)
	}
	scale := "00"
	if fp.Scale != 0 {
		scale = strconv.FormatUint(uint64(fp.Scale), 10)
	}
	return fmt.Sprintf("%d_%s_%s_%s", fp.Window, opts, mss, scale)
}

func (fp ja4tFingerprint) tcpOptions(tsVal uint32) ([]layers.TCPOption, error) {
	options := make([]layers.TCPOption, 0, len(fp.Kinds))
	for _, kind := range fp.Kinds {
		opt, err := tcpOption(kind, fp, tsVal)
		if err != nil {
			return nil, err
		}
		options = append(options, opt)
	}
	if n := tcpOptionBytes(options); n%4 != 0 {
		return nil, fmt.Errorf("TCP options length %d is not a multiple of 4", n)
	}
	return options, nil
}

func tcpOption(kind uint8, fp ja4tFingerprint, tsVal uint32) (layers.TCPOption, error) {
	switch kind {
	case 0:
		return layers.TCPOption{OptionType: layers.TCPOptionKindEndList}, nil
	case 1:
		return layers.TCPOption{OptionType: layers.TCPOptionKindNop}, nil
	case 2:
		var data [2]byte
		binary.BigEndian.PutUint16(data[:], fp.MSS)
		return layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionData: data[:]}, nil
	case 3:
		return layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionData: []byte{fp.Scale}}, nil
	case 4:
		return layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted}, nil
	case 8:
		var data [8]byte
		binary.BigEndian.PutUint32(data[:4], tsVal)
		return layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionData: data[:]}, nil
	default:
		return layers.TCPOption{}, fmt.Errorf("unsupported TCP option kind %d", kind)
	}
}

func tcpOptionBytes(options []layers.TCPOption) int {
	n := 0
	for _, option := range options {
		switch option.OptionType {
		case 0, 1:
			n++
		default:
			n += 2 + len(option.OptionData)
		}
	}
	return n
}

func parseJA4TRetransmit(value string) ([]time.Duration, error) {
	if value == "" {
		return nil, fmt.Errorf("invalid JA4T retransmit %q", value)
	}
	fields := strings.Split(value, "-")
	out := make([]time.Duration, 0, len(fields))
	for _, field := range fields {
		ms, err := strconv.ParseUint(field, 10, 32)
		if err != nil || ms == 0 {
			return nil, fmt.Errorf("invalid JA4T retransmit delay %q", field)
		}
		out = append(out, time.Duration(ms)*time.Millisecond)
	}
	return out, nil
}

func fingerprintHasKind(fp ja4tFingerprint, kind uint8) bool {
	for _, k := range fp.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}
