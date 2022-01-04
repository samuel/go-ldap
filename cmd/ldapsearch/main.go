package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/samuel/go-ldap/cmd/internal/ldapcmd"
	"github.com/samuel/go-ldap/ldap"
)

var (
	flagBaseDN = flag.String("b", "", "base dn for search")
	flagScope  = flag.String("s", "sub", "one of base, one, sub or children (search scope)")
)

var scopes = map[string]ldap.Scope{
	"base":     ldap.ScopeBaseObject,
	"one":      ldap.ScopeSingleLevel,
	"sub":      ldap.ScopeWholeSubtree,
	"children": ldap.ScopeChildren,
}

func main() {
	log.SetFlags(0)
	flag.Parse()

	req := &ldap.SearchRequest{
		BaseDN: *flagBaseDN,
	}

	// Parse args either as "filter attribute,attribute,..." or either by itself. A filter
	// string always start with a '('
	n := 0
	if flag.NArg() > n {
		s := flag.Arg(n)
		if len(s) > 0 && s[0] == '(' {
			n++
			f, err := ldap.ParseFilter(s)
			if err != nil {
				log.Fatalf("Failed to parse filter '%s': %s", s, err.Error())
			}
			req.Filter = f
		}
	}
	if flag.NArg() > n {
		attr := strings.Split(flag.Arg(n), ",")
		req.Attributes = make(map[string]bool)
		for _, a := range attr {
			req.Attributes[a] = true
		}
	}

	var ok bool
	req.Scope, ok = scopes[*flagScope]
	if !ok {
		log.Fatalf("Unknown scope %s", *flagScope)
	}

	cli, err := ldapcmd.Connect()
	if err != nil {
		log.Fatal(err)
	}

	res, err := cli.Search(req)
	if err != nil {
		log.Fatalf("Search failed: %s", err.Error())
	}
	for i, r := range res {
		if i != 0 {
			fmt.Println()
		}
		_ = r.ToLDIF(os.Stdout)
	}
}
