package curlu

import (
	"fmt"
	"strconv"
	"strings"
)

// maxGlobURLs bounds how many URLs one argument may expand to.
const maxGlobURLs = 1000

// expandGlob expands curl-style {a,b} sets and [N-M] numeric ranges in the
// path and query of raw, in curl order: the rightmost pattern varies fastest.
// A backslash makes the next {, }, [, ] or , literal. The scheme and
// authority are never globbed, so IPv6 literals need no -g.
func expandGlob(raw string) ([]string, error) {
	pathStart := len(raw)
	if scheme := strings.Index(raw, "://"); scheme >= 0 {
		if slash := strings.IndexAny(raw[scheme+3:], "/?"); slash >= 0 {
			pathStart = scheme + 3 + slash
		}
	}
	out := []string{raw[:pathStart]}
	rest := raw[pathStart:]
	var literal strings.Builder
	flush := func() {
		for i := range out {
			out[i] += literal.String()
		}
		literal.Reset()
	}
	for len(rest) > 0 {
		c := rest[0]
		switch c {
		case '\\':
			if len(rest) > 1 && strings.IndexByte("{}[],", rest[1]) >= 0 {
				literal.WriteByte(rest[1])
				rest = rest[2:]
				continue
			}
		case '{', '[':
			closer := byte('}')
			if c == '[' {
				closer = ']'
			}
			end := strings.IndexByte(rest, closer)
			if end < 0 {
				return nil, fmt.Errorf("unmatched %c in URL", c)
			}
			var items []string
			var err error
			if c == '{' {
				items = strings.Split(rest[1:end], ",")
			} else {
				items, err = expandRange(rest[1:end])
				if err != nil {
					return nil, err
				}
			}
			if len(out)*len(items) > maxGlobURLs {
				return nil, fmt.Errorf("URL expands to more than %d URLs", maxGlobURLs)
			}
			flush()
			next := make([]string, 0, len(out)*len(items))
			for _, prefix := range out {
				for _, item := range items {
					next = append(next, prefix+item)
				}
			}
			out = next
			rest = rest[end+1:]
			continue
		case '}', ']':
			return nil, fmt.Errorf("unmatched %c in URL", c)
		}
		literal.WriteByte(c)
		rest = rest[1:]
	}
	flush()
	return out, nil
}

// expandRange expands N-M; a zero-padded N (as in 01-10) pads every item.
func expandRange(spec string) ([]string, error) {
	lo, hi, ok := strings.Cut(spec, "-")
	first, err1 := strconv.ParseUint(lo, 10, 32)
	last, err2 := strconv.ParseUint(hi, 10, 32)
	if !ok || err1 != nil || err2 != nil || first > last {
		return nil, fmt.Errorf("bad range [%s] in URL", spec)
	}
	if last-first >= maxGlobURLs {
		return nil, fmt.Errorf("URL expands to more than %d URLs", maxGlobURLs)
	}
	width := 0
	if len(lo) > 1 && lo[0] == '0' {
		width = len(lo)
	}
	items := make([]string, 0, last-first+1)
	for n := first; n <= last; n++ {
		items = append(items, fmt.Sprintf("%0*d", width, n))
	}
	return items, nil
}
