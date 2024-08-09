package ldap_test

import (
	"testing"

	"github.com/samuel/go-ldap/ldap"
)

func TestClientBind(t *testing.T) {
	t.Parallel()
	c, err := ldap.Dial("tcp", "127.0.0.1:1389")
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
	t.Parallel()
	c, err := ldap.Dial("tcp", "127.0.0.1:1389")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Delete("cn=test"); err != nil {
		t.Fatal(err)
	}
}

func TestClientSearch(t *testing.T) {
	t.Parallel()
	c, err := ldap.Dial("tcp", "127.0.0.1:1389")
	if err != nil {
		t.Fatal(err)
	}
	req := &ldap.SearchRequest{
		Scope: ldap.ScopeWholeSubtree,
	}
	if res, err := c.Search(req); err != nil {
		t.Fatal(err)
	} else {
		for _, r := range res {
			t.Logf("%+v\n", r)
		}
	}
}
