package curlu

import (
	"encoding/binary"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
)

func TestParseJA4T(t *testing.T) {
	tests := []struct {
		in, out string
	}{
		{"64240_2-4-8-1-3_1460_7", "64240_2-4-8-1-3_1460_7"},
		{"64240_2-1-3-1-1-4_1460_8", "64240_2-1-3-1-1-4_1460_8"},
		{"65535_2-1-3-1-1-8-4-0-0_1460_6", "65535_2-1-3-1-1-8-4-0-0_1460_6"},
		{"8192_00_00_00", "8192_00_00_00"},
		{"5744_2-4-8-1-3_1436_00", "5744_2-4-8-1-3_1436_00"},
		{"65535_2_8_00", "65535_2_08_00"},
	}
	for _, tc := range tests {
		fp, err := parseJA4T(tc.in)
		if err != nil {
			t.Fatalf("parseJA4T(%q): %v", tc.in, err)
		}
		if got := fp.String(); got != tc.out {
			t.Errorf("parseJA4T(%q).String() = %q, want %q", tc.in, got, tc.out)
		}
	}
}

func TestParseJA4TErrors(t *testing.T) {
	for _, in := range []string{
		"", "1_2_3", "65536_00_00_00", "1_2-4_00_00",
		"1_2-99_1460_00", "1_2-3_1460_7", "1_00_1460_00",
		"1_2-4-8-1-3_00_7", "1_1-1_00_00",
	} {
		if _, err := parseJA4T(in); err == nil {
			t.Errorf("parseJA4T(%q) unexpectedly succeeded", in)
		}
	}
}

func TestParseJA4TRetransmit(t *testing.T) {
	got, err := parseJA4TRetransmit("1000-2000-4000")
	if err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, in := range []string{"", "0", "1000-0", "abc", "1000-"} {
		if _, err := parseJA4TRetransmit(in); err == nil {
			t.Errorf("parseJA4TRetransmit(%q) unexpectedly succeeded", in)
		}
	}
}

func TestSYNGoldenFingerprints(t *testing.T) {
	ja4tNow = func() time.Time { return time.UnixMilli(0x01020304) }
	t.Cleanup(func() { ja4tNow = time.Now })

	src := net.IPv4(10, 0, 0, 1).To4()
	dst := net.IPv4(10, 0, 0, 2).To4()
	for _, fp := range []string{
		"64240_2-4-8-1-3_1460_7",
		"64240_2-1-3-1-1-4_1460_8",
		"65535_2-1-3-1-1-8-4-0-0_1460_6",
		"8192_00_00_00",
		"5744_2-4-8-1-3_1436_00",
	} {
		parsed, err := parseJA4T(fp)
		if err != nil {
			t.Fatal(err)
		}
		options, err := parsed.tcpOptions(uint32(ja4tNow().UnixMilli()))
		if err != nil {
			t.Fatalf("%s: options: %v", fp, err)
		}
		raw, err := serializeSegment(src, dst, 12345, 80, 1, 0, parsed.Window, 1, true, false, false, false, options, nil)
		if err != nil {
			t.Fatalf("%s: build: %v", fp, err)
		}
		_, tcp, _, err := parseIPv4TCP(raw)
		if err != nil {
			t.Fatalf("%s: parse: %v", fp, err)
		}
		if !tcp.SYN || tcp.ACK {
			t.Fatalf("%s: flags SYN=%v ACK=%v", fp, tcp.SYN, tcp.ACK)
		}
		if tcp.Window != parsed.Window {
			t.Fatalf("%s: window %d", fp, tcp.Window)
		}
		if tcp.Checksum == 0 {
			t.Fatalf("%s: checksum is zero", fp)
		}
		got := fingerprintFromSYN(tcp)
		if got != parsed.String() {
			t.Fatalf("%s: on-wire %q, want %q (kinds=%v)", fp, got, parsed.String(), optionKindsFromHeader(tcp))
		}
	}
}

func fingerprintFromSYN(tcp *layers.TCP) string {
	fp := ja4tFingerprint{Window: tcp.Window, Kinds: optionKindsFromHeader(tcp)}
	for _, option := range tcp.Options {
		switch option.OptionType {
		case layers.TCPOptionKindMSS:
			if len(option.OptionData) >= 2 {
				fp.MSS = binary.BigEndian.Uint16(option.OptionData)
			}
		case layers.TCPOptionKindWindowScale:
			if len(option.OptionData) >= 1 {
				fp.Scale = option.OptionData[0]
			}
		}
	}
	return fp.String()
}

func optionKindsFromHeader(tcp *layers.TCP) []uint8 {
	data := tcp.Contents
	if len(data) < 20 {
		return nil
	}
	data = data[20:]
	var kinds []uint8
	for len(data) > 0 {
		kind := data[0]
		kinds = append(kinds, kind)
		switch kind {
		case 0, 1:
			data = data[1:]
		default:
			if len(data) < 2 {
				return kinds
			}
			n := int(data[1])
			if n < 2 || n > len(data) {
				return kinds
			}
			data = data[n:]
		}
	}
	return kinds
}
