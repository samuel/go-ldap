package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/samuel/go-ldap/cmd/internal/ldapcmd"
)

func main() {
	flag.Parse()

	ctx := context.Background()
	cli, err := ldapcmd.Connect(ctx)
	if err != nil {
		slog.Error("failed to connect", "err", err)
		os.Exit(1)
	}

	id, err := cli.WhoAmI(ctx)
	if err != nil {
		slog.Error("whoami failed", "err", err)
		os.Exit(1)
	}
	fmt.Println(id)
}
