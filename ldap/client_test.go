package ldap

import "testing"

func TestClientBind(t *testing.T) {
	c, err := Dial("tcp", "127.0.0.1:1389")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Bind("cn=test", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Bind("cn=test", []byte("verysecure")); err != nil {
		t.Fatal(err)
	}
}

func TestClientDelete(t *testing.T) {
	c, err := Dial("tcp", "127.0.0.1:1389")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Delete("cn=test"); err != nil {
		t.Fatal(err)
	}
}

func TestClientSearch(t *testing.T) {
	c, err := Dial("tcp", "127.0.0.1:1389")
	if err != nil {
		t.Fatal(err)
	}
	req := &SearchRequest{
		Scope: ScopeWholeSubtree,
	}
	if res, err := c.Search(req); err != nil {
		t.Fatal(err)
	} else {
		for _, r := range res {
			t.Logf("%+v\n", r)
		}
	}
}
