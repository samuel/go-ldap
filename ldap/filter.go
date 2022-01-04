package ldap

// TODO: better validation especially of attribute names

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	filterTagAND             = 0
	filterTagOR              = 1
	filterTagNOT             = 2
	filterTagEqualityMatch   = 3
	filterTagSubstrings      = 4
	filterTagGreaterOrEqual  = 5
	filterTagLessOrEqual     = 6
	filterTagPresent         = 7
	filterTagApproxMatch     = 8
	filterTagExtensibleMatch = 9
)

type ErrFilterSyntaxError struct {
	Pos int
	Msg string
}

func (e *ErrFilterSyntaxError) Error() string {
	return fmt.Sprintf("ldap: filter syntax error at position %d: %s", e.Pos, e.Msg)
}

type Filter interface {
	String() string
	Encode() (*Packet, error)
}

type AND struct {
	Filters []Filter
}

func (a *AND) String() string {
	s := make([]string, len(a.Filters))
	for i, f := range a.Filters {
		s[i] = f.String()
	}
	return fmt.Sprintf("(&%s)", strings.Join(s, ""))
}

func (a *AND) Encode() (*Packet, error) {
	pkt := NewPacket(ClassContext, false, filterTagAND, nil)
	for _, f := range a.Filters {
		p, err := f.Encode()
		if err != nil {
			return nil, err
		}
		pkt.AddItem(p)
	}
	return pkt, nil
}

type OR struct {
	Filters []Filter
}

func (o *OR) Encode() (*Packet, error) {
	pkt := NewPacket(ClassContext, false, filterTagOR, nil)
	for _, f := range o.Filters {
		p, err := f.Encode()
		if err != nil {
			return nil, err
		}
		pkt.AddItem(p)
	}
	return pkt, nil
}

func (o *OR) String() string {
	s := make([]string, len(o.Filters))
	for i, f := range o.Filters {
		s[i] = f.String()
	}
	return fmt.Sprintf("(|%s)", strings.Join(s, ""))
}

type NOT struct {
	Filter
}

func (n *NOT) Encode() (*Packet, error) {
	pkt := NewPacket(ClassContext, false, filterTagNOT, nil)
	p, err := n.Filter.Encode()
	if err != nil {
		return nil, err
	}
	pkt.AddItem(p)
	return pkt, nil
}

func (n *NOT) String() string {
	return fmt.Sprintf("(!%s)", n.Filter.String())
}

type AttributeValueAssertion struct {
	Attribute string
	Value     []byte
}

type EqualityMatch AttributeValueAssertion

func (f *EqualityMatch) Encode() (*Packet, error) {
	pkt := NewPacket(ClassContext, false, filterTagEqualityMatch, nil)
	pkt.AddItem(NewPacket(ClassUniversal, true, TagOctetString, f.Attribute))
	pkt.AddItem(NewPacket(ClassUniversal, true, TagOctetString, f.Value))
	return pkt, nil
}

func (f *EqualityMatch) String() string {
	return fmt.Sprintf("(%s=%s)", filterEscape(f.Attribute), filterEscape(string(f.Value)))
}

type GreaterOrEqual AttributeValueAssertion

func (f *GreaterOrEqual) Encode() (*Packet, error) {
	pkt := NewPacket(ClassContext, false, filterTagGreaterOrEqual, nil)
	pkt.AddItem(NewPacket(ClassUniversal, true, TagOctetString, f.Attribute))
	pkt.AddItem(NewPacket(ClassUniversal, true, TagOctetString, f.Value))
	return pkt, nil
}

func (f *GreaterOrEqual) String() string {
	return fmt.Sprintf("(%s>=%s)", filterEscape(f.Attribute), filterEscape(string(f.Value)))
}

type LessOrEqual AttributeValueAssertion

func (f *LessOrEqual) Encode() (*Packet, error) {
	pkt := NewPacket(ClassContext, false, filterTagLessOrEqual, nil)
	pkt.AddItem(NewPacket(ClassUniversal, true, TagOctetString, f.Attribute))
	pkt.AddItem(NewPacket(ClassUniversal, true, TagOctetString, f.Value))
	return pkt, nil
}

func (f *LessOrEqual) String() string {
	return fmt.Sprintf("(%s<=%s)", filterEscape(f.Attribute), filterEscape(string(f.Value)))
}

type ApproxMatch AttributeValueAssertion

func (f *ApproxMatch) Encode() (*Packet, error) {
	pkt := NewPacket(ClassContext, false, filterTagApproxMatch, nil)
	pkt.AddItem(NewPacket(ClassUniversal, true, TagOctetString, f.Attribute))
	pkt.AddItem(NewPacket(ClassUniversal, true, TagOctetString, f.Value))
	return pkt, nil
}

func (f *ApproxMatch) String() string {
	return fmt.Sprintf("(%s~=%s)", filterEscape(f.Attribute), filterEscape(string(f.Value)))
}

type Present struct {
	Attribute string
}

func (f *Present) Encode() (*Packet, error) {
	return NewPacket(ClassContext, true, filterTagPresent, f.Attribute), nil
}

func (f *Present) String() string {
	return fmt.Sprintf("(%s=*)", filterEscape(f.Attribute))
}

type Substrings struct {
	Attribute string
	Initial   string
	Final     string
	Any       []string
}

func (f *Substrings) Encode() (*Packet, error) {
	pkt := NewPacket(ClassContext, false, filterTagSubstrings, nil)
	pkt.AddItem(NewPacket(ClassUniversal, true, TagOctetString, f.Attribute))
	p := pkt.AddItem(NewPacket(ClassUniversal, false, TagSequence, nil))
	if f.Initial != "" {
		p.AddItem(NewPacket(ClassContext, true, 0, f.Initial))
	}
	for _, a := range f.Any {
		if a != "" {
			p.AddItem(NewPacket(ClassContext, true, 1, a))
		}
	}
	if f.Final != "" {
		p.AddItem(NewPacket(ClassContext, true, 2, f.Final))
	}
	return pkt, nil
}

func (s *Substrings) String() string {
	n := len(s.Any) + 2
	parts := make([]string, n)
	parts[0] = filterEscape(s.Initial)
	parts[len(parts)-1] = filterEscape(s.Final)
	for i, s := range s.Any {
		parts[i+1] = filterEscape(s)
	}
	return fmt.Sprintf("(%s=%s)", filterEscape(s.Attribute), strings.Join(parts, "*"))
}

type tokenizer struct {
	s    string
	pos  int // byte position
	cpos int // character position
}

func (t *tokenizer) next() rune {
	if t.pos == len(t.s) {
		return 0
	}
	r, size := utf8.DecodeRuneInString(t.s[t.pos:])
	t.pos += size
	t.cpos++
	return r
}

var escapes = map[rune][]rune{
	'(':  []rune(`\28`),
	')':  []rune(`\29`),
	'&':  []rune(`\26`),
	'|':  []rune(`\3c`),
	'=':  []rune(`\3d`),
	'>':  []rune(`\3e`),
	'<':  []rune(`\3c`),
	'~':  []rune(`\7e`),
	'*':  []rune(`\2a`),
	'/':  []rune(`\2f`),
	'\\': []rune(`\5c`),
}

func filterEscape(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if e := escapes[r]; e != nil {
			out = append(out, e...)
		} else {
			out = append(out, r)
		}
	}
	return string(out)
}

func ParseFilter(filter string) (Filter, error) {
	if len(filter) == 0 {
		return nil, &ErrFilterSyntaxError{Pos: 0, Msg: "empty filter"}
	}
	tok := &tokenizer{s: filter}
	return parseFilter(tok, false)
}

func parseFilter(tok *tokenizer, checkClose bool) (Filter, error) {
	r := tok.next()
	if checkClose && r == ')' {
		tok.pos--
		return nil, nil
	} else if r != '(' {
		return nil, &ErrFilterSyntaxError{Pos: tok.cpos - 1, Msg: "expected ("}
	}
	var filter Filter
	r = tok.next()
	switch r {
	case 0, utf8.RuneError:
		return nil, &ErrFilterSyntaxError{Pos: tok.cpos, Msg: "unxpected end of filter"}
	case '&', '|':
		var filters []Filter
		for {
			f, err := parseFilter(tok, true)
			if err != nil {
				return nil, err
			}
			if f == nil {
				break
			}
			filters = append(filters, f)
		}
		switch r {
		case '&':
			filter = &AND{Filters: filters}
		case '|':
			filter = &OR{Filters: filters}
		}
	case '!':
		f, err := parseFilter(tok, false)
		if err != nil {
			return nil, err
		}
		filter = &NOT{Filter: f}
	default:
		name := []rune{r}
		var op string
		for op == "" {
			r = tok.next()
			switch r {
			case 0, utf8.RuneError:
				return nil, &ErrFilterSyntaxError{Pos: tok.cpos, Msg: "unxpected end of filter"}
			case '=':
				op = "="
			case '>', '<', '~':
				op = string(r) + "="
				if r2 := tok.next(); r2 != '=' {
					return nil, &ErrFilterSyntaxError{Pos: tok.cpos - 1, Msg: "expected = after " + string(r)}
				}
			case '\\':
				// hex code
				r1 := tok.next()
				r2 := tok.next()
				if r1 == 0 || r2 == 0 || r1 == utf8.RuneError || r2 == utf8.RuneError {
					return nil, &ErrFilterSyntaxError{Pos: tok.cpos, Msg: "unxpected end of filter"}
				}
				h := string(r1) + string(r2)
				n, err := strconv.ParseInt(h, 16, 8)
				if err != nil {
					return nil, &ErrFilterSyntaxError{Pos: tok.cpos - 2, Msg: "unable to parse hex code: " + err.Error()}
				}
				name = append(name, rune(n))
			default:
				name = append(name, r)
			}
		}
		var value []rune
		hasStar := false
	valueLoop:
		for {
			r = tok.next()
			if r == '*' {
				hasStar = true
			}
			switch r {
			case 0, utf8.RuneError:
				return nil, &ErrFilterSyntaxError{Pos: tok.cpos, Msg: "unxpected end of filter"}
			case ')':
				tok.pos--
				break valueLoop
			case '\\':
				// hex code
				r1 := tok.next()
				r2 := tok.next()
				if r1 == 0 || r2 == 0 || r1 == utf8.RuneError || r2 == utf8.RuneError {
					return nil, &ErrFilterSyntaxError{Pos: tok.cpos, Msg: "unxpected end of filter"}
				}
				h := string(r1) + string(r2)
				n, err := strconv.ParseInt(h, 16, 8)
				if err != nil {
					return nil, &ErrFilterSyntaxError{Pos: tok.cpos - 2, Msg: "unable to parse hex code: " + err.Error()}
				}
				value = append(value, rune(n))
			default:
				value = append(value, r)
			}
		}
		nameS := string(name)
		valueS := string(value)
		if valueS == "*" {
			if op != "=" {
				return nil, &ErrFilterSyntaxError{Pos: tok.cpos, Msg: "* value for non = op"}
			}
			filter = &Present{Attribute: nameS}
		} else if hasStar {
			if op != "=" {
				return nil, &ErrFilterSyntaxError{Pos: tok.cpos, Msg: "non equality substring match not allowed"}
			}
			// substring match
			parts := strings.Split(valueS, "*")
			filter = &Substrings{
				Attribute: nameS,
				Initial:   parts[0],
				Final:     parts[len(parts)-1],
				Any:       parts[1 : len(parts)-1],
			}
		} else {
			switch op {
			case "=":
				filter = &EqualityMatch{Attribute: nameS, Value: []byte(valueS)}
			case ">=":
				filter = &GreaterOrEqual{Attribute: nameS, Value: []byte(valueS)}
			case "<=":
				filter = &LessOrEqual{Attribute: nameS, Value: []byte(valueS)}
			case "~=":
				filter = &ApproxMatch{Attribute: nameS, Value: []byte(valueS)}
			}
		}
	}
	if r := tok.next(); r != ')' {
		return nil, &ErrFilterSyntaxError{Pos: tok.cpos - 1, Msg: "expected )"}
	}
	return filter, nil
}

func parseSearchFilter(pkt *Packet) (Filter, error) {
	switch pkt.Tag {
	case filterTagAND:
		fAnd := &AND{}
		for _, c := range pkt.Items {
			f, err := parseSearchFilter(c)
			if err != nil {
				return nil, err
			}
			fAnd.Filters = append(fAnd.Filters, f)
		}
		return fAnd, nil
	case filterTagOR:
		fOr := &OR{}
		for _, c := range pkt.Items {
			f, err := parseSearchFilter(c)
			if err != nil {
				return nil, err
			}
			fOr.Filters = append(fOr.Filters, f)
		}
		return fOr, nil
	case filterTagNOT:
		f, err := parseSearchFilter(pkt.Items[0])
		if err != nil {
			return nil, err
		}
		return &NOT{
			Filter: f,
		}, nil
	case filterTagEqualityMatch:
		var ok bool
		f := &EqualityMatch{}
		if f.Attribute, ok = pkt.Items[0].Str(); !ok {
			return nil, ProtocolError("failed to parse equalityMatch.attribute in filter")
		}
		if f.Value, ok = pkt.Items[1].Bytes(); !ok {
			return nil, ProtocolError("failed to parse equalityMatch.value in filter")
		}
		return f, nil
	case filterTagSubstrings:
		var ok bool
		q := &Substrings{}
		if q.Attribute, ok = pkt.Items[0].Str(); !ok {
			return nil, ProtocolError("failed to parse substrings.attribute in filter")
		}
		for i, c := range pkt.Items[1].Items {
			switch c.Tag {
			case 0: // initial
				if i != 0 {
					return nil, ProtocolError("search filter substrings has final as non-first child")
				}
				var ok bool
				if q.Initial, ok = c.Str(); !ok {
					return nil, ProtocolError("failed to parse initial in search filter")
				}
			case 1: // Any
				s, ok := c.Str()
				if !ok {
					return nil, ProtocolError("failed to parse any in search filter")
				}
				q.Any = append(q.Any, s)
			case 2: // Final
				if i != len(pkt.Items[1].Items)-1 {
					return nil, ProtocolError("search filter substrings has final as non-last child")
				}
				var ok bool
				if q.Final, ok = c.Str(); !ok {
					return nil, ProtocolError("failed to parse final in search filter")
				}
			default:
				return nil, ProtocolError(fmt.Sprintf("unknown filter substring type %d", c.Tag))
			}
		}
		return q, nil
	case filterTagGreaterOrEqual:
		var ok bool
		f := &GreaterOrEqual{}
		if f.Attribute, ok = pkt.Items[0].Str(); !ok {
			return nil, ProtocolError("failed to parse greaterOrEqual.attribute in filter")
		}
		if f.Value, ok = pkt.Items[1].Bytes(); !ok {
			return nil, ProtocolError("failed to parse greaterOrEqual.value in filter")
		}
		return f, nil
	case filterTagLessOrEqual:
		var ok bool
		f := &LessOrEqual{}
		if f.Attribute, ok = pkt.Items[0].Str(); !ok {
			return nil, ProtocolError("failed to parse lessOrEqual.attribute in filter")
		}
		if f.Value, ok = pkt.Items[1].Bytes(); !ok {
			return nil, ProtocolError("failed to parse lessOrEqual.value in filter")
		}
		return f, nil
	case filterTagPresent:
		attr, ok := pkt.Str()
		if !ok {
			return nil, ProtocolError("failed to parse present in search filter")
		}
		return &Present{
			Attribute: attr,
		}, nil
	case filterTagApproxMatch:
		var ok bool
		f := &ApproxMatch{}
		if f.Attribute, ok = pkt.Items[0].Str(); !ok {
			return nil, ProtocolError("failed to parse approxMatch.attribute in filter")
		}
		if f.Value, ok = pkt.Items[1].Bytes(); !ok {
			return nil, ProtocolError("failed to parse approxMatch.value in filter")
		}
		return f, nil
	case filterTagExtensibleMatch:
		// TODO
	}
	return nil, ProtocolError(fmt.Sprintf("unknown filter tag %d", pkt.Tag))
}
