package ldap

import "testing"

func TestParseFilter(t *testing.T) {
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
