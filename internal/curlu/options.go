package curlu

import (
	"fmt"
	"strings"
	"time"
)

type Options struct {
	Include        bool
	Silent         bool
	ShowError      bool
	Headers        []string
	ConnectTimeout time.Duration
	MaxTime        time.Duration
	URL            string
	Help           bool
	Version        bool
}

func ParseArgs(args []string) (Options, error) {
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
	if !opts.Help && !opts.Version && opts.URL == "" {
		return opts, fmt.Errorf("no URL specified")
	}
	return opts, nil
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

func setURL(opts *Options, value string) error {
	if opts.URL != "" {
		return fmt.Errorf("only one URL is supported")
	}
	opts.URL = value
	return nil
}

func parseSeconds(value string) (time.Duration, error) {
	if strings.HasPrefix(value, "-") {
		return 0, fmt.Errorf("timeout must not be negative")
	}
	d, err := time.ParseDuration(value + "s")
	if err != nil {
		return 0, fmt.Errorf("invalid timeout %q", value)
	}
	return d, nil
}
