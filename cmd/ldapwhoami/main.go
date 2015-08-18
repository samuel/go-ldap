package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/samuel/go-ldap/cmd/internal/ldapcmd"
)

func main() {
	log.SetFlags(0)
	flag.Parse()

	cli, err := ldapcmd.Connect()
	if err != nil {
		log.Fatal(err)
	}

	id, err := cli.WhoAmI()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(id)
}
