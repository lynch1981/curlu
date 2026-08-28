package curlu

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

type Options struct {
	Include        bool
	Silent         bool
	ShowError      bool
	Verbose        bool
	Headers        []string
	ConnectTimeout time.Duration
	MaxTime        time.Duration
	UTLSHello      utls.ClientHelloID
	UTLSCiphers    []uint16
	UTLSHelloList  bool
	UTLSInfo       bool
	URL            string
	Help           bool
	Version        bool
}

func ParseArgs(args []string) (Options, error) {
	args = expandCombinedFlags(args)
	var opts Options
	positional := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if positional || arg == "-" || !strings.HasPrefix(arg, "-") {
			if err := setURL(&opts, arg); err != nil {
				return opts, err
			}
			continue
		}
		if arg == "--" {
			positional = true
			continue
		}
		if strings.HasPrefix(arg, "--") {
			name, value, hasValue := strings.Cut(arg[2:], "=")
			switch name {
			case "include":
				if hasValue {
					return opts, optionValueError(name)
				}
				opts.Include = true
			case "header":
				var err error
				value, i, err = optionArgument(args, i, name, value, hasValue)
				if err != nil {
					return opts, err
				}
				opts.Headers = append(opts.Headers, value)
			case "silent":
				if hasValue {
					return opts, optionValueError(name)
				}
				opts.Silent = true
			case "show-error":
				if hasValue {
					return opts, optionValueError(name)
				}
				opts.ShowError = true
			case "verbose":
				if hasValue {
					return opts, optionValueError(name)
				}
				opts.Verbose = true
			case "connect-timeout", "max-time":
				var err error
				value, i, err = optionArgument(args, i, name, value, hasValue)
				if err != nil {
					return opts, err
				}
				duration, err := parseSeconds(value)
				if err != nil {
					return opts, fmt.Errorf("option --%s: %w", name, err)
				}
				if name == "connect-timeout" {
					opts.ConnectTimeout = duration
				} else {
					opts.MaxTime = duration
				}
			case "utls-hello":
				var err error
				value, i, err = optionArgument(args, i, name, value, hasValue)
				if err != nil {
					return opts, err
				}
				id, _, ok := resolveUTLSHello(value)
				if !ok {
					return opts, fmt.Errorf("option --%s: unknown ClientHello ID %q", name, value)
				}
				opts.UTLSHello = id
			case "utls-cipher-append":
				var err error
				value, i, err = optionArgument(args, i, name, value, hasValue)
				if err != nil {
					return opts, err
				}
				cipher, err := parseCipherID(value)
				if err != nil {
					return opts, fmt.Errorf("option --%s: %w", name, err)
				}
				opts.UTLSCiphers = append(opts.UTLSCiphers, cipher)
			case "utls-hello-list":
				if hasValue {
					return opts, optionValueError(name)
				}
				opts.UTLSHelloList = true
			case "utls-info":
				if hasValue {
					return opts, optionValueError(name)
				}
				opts.UTLSInfo = true
			case "http2-prior-knowledge", "insecure":
				// Accepted so Test::Nginx can invoke curlu as `curl`.
				// HTTPS verification is always disabled; ALPN comes from the parrot.
				if hasValue {
					return opts, optionValueError(name)
				}
			case "help":
				if hasValue {
					return opts, optionValueError(name)
				}
				opts.Help = true
			case "version":
				if hasValue {
					return opts, optionValueError(name)
				}
				opts.Version = true
			default:
				return opts, fmt.Errorf("unknown option --%s", name)
			}
			continue
		}
		short := arg[1:]
		for len(short) > 0 {
			flag := short[0]
			short = short[1:]
			switch flag {
			case 'i':
				opts.Include = true
			case 's':
				opts.Silent = true
			case 'S':
				opts.ShowError = true
			case 'v':
				opts.Verbose = true
			case 'k':
				// curl --insecure. curlu always skips certificate verification.
			case 'h':
				opts.Help = true
			case 'V':
				opts.Version = true
			case 'H', 'm':
				value := short
				if value == "" {
					if i+1 >= len(args) {
						return opts, fmt.Errorf("option -%c requires an argument", flag)
					}
					i++
					value = args[i]
				}
				short = ""
				if flag == 'H' {
					opts.Headers = append(opts.Headers, value)
				} else {
					var err error
					opts.MaxTime, err = parseSeconds(value)
					if err != nil {
						return opts, fmt.Errorf("option -m: %w", err)
					}
				}
			default:
				return opts, fmt.Errorf("unknown option -%c", flag)
			}
		}
	}
	if !opts.Help && !opts.Version && !opts.UTLSHelloList && opts.URL == "" {
		return opts, fmt.Errorf("no URL specified")
	}
	return opts, nil
}

func parseCipherID(value string) (uint16, error) {
	if len(value) != 6 || value[:2] != "0x" {
		return 0, fmt.Errorf("invalid cipher ID %q (expected 0xNNNN)", value)
	}
	cipher, err := strconv.ParseUint(value[2:], 16, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid cipher ID %q (expected 0xNNNN)", value)
	}
	return uint16(cipher), nil
}

func optionArgument(args []string, index int, name, value string, hasValue bool) (string, int, error) {
	if hasValue {
		return value, index, nil
	}
	if index+1 >= len(args) {
		return "", index, fmt.Errorf("option --%s requires an argument", name)
	}
	return args[index+1], index + 1, nil
}

func optionValueError(name string) error {
	return fmt.Errorf("option --%s does not take a value", name)
}

// expandCombinedFlags splits a single argv that contains spaces, matching
// Test::Nginx `--- curl_options` which is pushed as one token.
func expandCombinedFlags(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && strings.Contains(arg, " ") {
			out = append(out, strings.Fields(arg)...)
			continue
		}
		out = append(out, arg)
	}
	return out
}

func setURL(opts *Options, value string) error {
	if opts.URL != "" {
		return fmt.Errorf("only one URL is supported")
	}
	opts.URL = value
	return nil
}

func parseSeconds(value string) (time.Duration, error) {
	seconds, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return 0, fmt.Errorf("invalid timeout %q", value)
	}
	if seconds < 0 {
		return 0, fmt.Errorf("timeout must not be negative")
	}
	const maxSeconds = float64(math.MaxInt64) / float64(time.Second)
	if seconds > maxSeconds {
		return 0, fmt.Errorf("invalid timeout %q", value)
	}
	return time.Duration(seconds * float64(time.Second)), nil
}
