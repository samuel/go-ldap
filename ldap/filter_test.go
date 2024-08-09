package ldap

import (
	"bytes"
	"errors"
	"testing"
)

func TestParseFilter(t *testing.T) {
	t.Parallel()
	cases := []string{
		"(present=*)",
		"(less<=123)",
		"(greater>=123)",
		"(approx~=abc)",
		"(!(not=123))",
		"(&(abc=123)(easy<=hard))",
		"(|(abc=123)(easy<=hard))",
		"(escaped=\\28\\29)",
		"(substr=prefix*mid1*mid2*suffix)",
		"(prefix=prefix*)",
		"(suffix=*suffix)",
		"(middle=*middle*)",
	}
	for _, c := range cases {
		if f, err := ParseFilter(c); err != nil {
			t.Errorf("Failed to parse '%s': %s", c, err.Error())
		} else if f.String() != c {
			t.Errorf("Parse filter '%s' != '%s'", c, f.String())
		}
	}
}

func TestFilterEncoding(t *testing.T) {
	t.Parallel()
	cases := []Filter{
		&Present{
			Attribute: "attr",
		},
		&GreaterOrEqual{
			Attribute: "foo",
			Value:     []byte("bar"),
		},
		&LessOrEqual{
			Attribute: "foo",
			Value:     []byte("bar"),
		},
		&ApproxMatch{
			Attribute: "foo",
			Value:     []byte{1, 2, 3},
		},
		&NOT{Filter: &EqualityMatch{
			Attribute: "abc",
			Value:     []byte("123"),
		}},
		&AND{
			Filters: []Filter{&EqualityMatch{
				Attribute: "abc",
				Value:     []byte("123"),
			}},
		},
		&OR{
			Filters: []Filter{&EqualityMatch{
				Attribute: "or",
				Value:     []byte("123"),
			}},
		},
		&Substrings{
			Attribute: "attr",
			Initial:   "init",
			Final:     "final",
			Any:       []string{"one", "two"},
		},
	}
	for _, c := range cases {
		pkt, err := c.Encode()
		if err != nil {
			t.Fatal(err)
		}
		f, err := parseSearchFilter(pkt)
		if err != nil {
			t.Fatal(err)
		}
		if c.String() != f.String() {
			t.Errorf("'%s' != '%s'", f.String(), c.String())
		}
	}
}

func TestParseFilterHexEscape(t *testing.T) {
	t.Parallel()
	cases := []struct {
		filter string
		value  []byte
	}{
		{`(a=\c3\a9)`, []byte{0xc3, 0xa9}}, // UTF-8 "é" — bytes >= 0x80
		{`(a=\ff)`, []byte{0xff}},          // high byte that signed parsing used to reject
		{`(a=\00)`, []byte{0x00}},
	}
	for _, c := range cases {
		f, err := ParseFilter(c.filter)
		if err != nil {
			t.Errorf("ParseFilter(%q) failed: %s", c.filter, err)
			continue
		}
		eq, ok := f.(*EqualityMatch)
		if !ok {
			t.Errorf("ParseFilter(%q) = %T, want *EqualityMatch", c.filter, f)
			continue
		}
		if !bytes.Equal(eq.Value, c.value) {
			t.Errorf("ParseFilter(%q) value = % x, want % x", c.filter, eq.Value, c.value)
		}
	}
}

func TestFilterPipeEscape(t *testing.T) {
	t.Parallel()
	f := &EqualityMatch{Attribute: "x", Value: []byte("a|b")}
	const want = `(x=a\7cb)`
	if s := f.String(); s != want {
		t.Errorf("String() = %q, want %q", s, want)
	}
	f2, err := ParseFilter(want)
	if err != nil {
		t.Fatalf("ParseFilter(%q) failed: %s", want, err)
	}
	eq, ok := f2.(*EqualityMatch)
	if !ok {
		t.Fatalf("ParseFilter(%q) = %T, want *EqualityMatch", want, f2)
	}
	if !bytes.Equal(eq.Value, []byte("a|b")) {
		t.Errorf("round-trip value = % x, want %q", eq.Value, "a|b")
	}
}

func TestParseFilterEscapedStar(t *testing.T) {
	t.Parallel()
	// An escaped asterisk is a literal value, not a presence wildcard.
	f, err := ParseFilter(`(cn=\2a)`)
	if err != nil {
		t.Fatal(err)
	}
	eq, ok := f.(*EqualityMatch)
	if !ok {
		t.Fatalf("ParseFilter(`(cn=\\2a)`) = %T, want *EqualityMatch", f)
	}
	if string(eq.Value) != "*" {
		t.Errorf("value = %q, want %q", eq.Value, "*")
	}
	if got := f.String(); got != `(cn=\2a)` {
		t.Errorf("String() = %q, want %q", got, `(cn=\2a)`)
	}
}

func TestParseFilterSubstringEscapedStar(t *testing.T) {
	t.Parallel()
	// Escaped stars inside a substring filter are literal, only unescaped stars
	// split the segments: a\2ab*c => initial "a*b", final "c".
	f, err := ParseFilter(`(cn=a\2ab*c)`)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := f.(*Substrings)
	if !ok {
		t.Fatalf("ParseFilter = %T, want *Substrings", f)
	}
	if s.Initial != "a*b" || s.Final != "c" || len(s.Any) != 0 {
		t.Errorf("Initial=%q Final=%q Any=%v, want Initial=%q Final=%q Any=[]", s.Initial, s.Final, s.Any, "a*b", "c")
	}
}

func TestParseSearchFilterMalformed(t *testing.T) {
	t.Parallel()
	octet := func(s string) *Packet { return NewPacket(ClassUniversal, true, TagOctetString, s) }

	notEmpty := NewPacket(ClassContext, false, filterTagNOT, nil)

	eqOne := NewPacket(ClassContext, false, filterTagEqualityMatch, nil)
	eqOne.AddItem(octet("attr"))

	subOne := NewPacket(ClassContext, false, filterTagSubstrings, nil)
	subOne.AddItem(octet("attr"))

	// These previously panicked on out-of-range index access; they must now
	// return a ProtocolError instead.
	for _, pkt := range []*Packet{notEmpty, eqOne, subOne} {
		f, err := parseSearchFilter(pkt)
		if err == nil {
			t.Errorf("parseSearchFilter(tag %d) = %v, want error", pkt.Tag, f)
			continue
		}
		var pe *ProtocolError
		if !errors.As(err, &pe) {
			t.Errorf("parseSearchFilter(tag %d) error = %T, want *ProtocolError", pkt.Tag, err)
		}
	}
}
