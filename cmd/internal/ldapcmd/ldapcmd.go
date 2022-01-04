package ldapcmd

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/howeyc/gopass"
	"github.com/samuel/go-ldap/ldap"
)

var (
	flagBindDN     = flag.String("D", "", "bind DN")
	flagBindPass   = flag.String("w", "", "bind password (for simple authentication)")
	flagHost       = flag.String("h", "127.0.0.1", "LDAP server")
	flagInsecure   = flag.Bool("insecure", false, "Don't validate server certificate")
	flagPort       = flag.Int("p", 389, "port on LDAP server")
	flagPromptPass = flag.Bool("W", false, "prompt for bind password")
	flagSimpleAuth = flag.Bool("x", false, "Simple authentication")
	flagStartTLS   = flag.Bool("Z", false, "Start TLS request (-ZZ to require successful response)") // TODO: implement ZZ
	flagURI        = flag.String("H", "", "LDAP Uniform Resource Identifier(s)")
)

// Connect connects to the LDAP server. flag.Parse must
// have been called first.
func Connect() (*ldap.Client, error) {
	addr := *flagHost
	enableTLS := false
	if *flagURI != "" {
		u, err := url.Parse(*flagURI)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse URI %s: %s", *flagURI, err.Error())
		}
		if u.Scheme == "ldaps" {
			enableTLS = true
			if *flagPort == 389 {
				*flagPort = 636
			}
		} else if u.Scheme != "ldap" {
			return nil, fmt.Errorf("URI scheme must be ldap or ldaps: %s", *flagURI)
		}
		addr = u.Host
	}
	if strings.IndexByte(addr, ':') < 0 {
		addr += ":" + strconv.Itoa(*flagPort)
	}
	var err error
	var cli *ldap.Client
	if enableTLS {
		conf := &tls.Config{
			InsecureSkipVerify: *flagInsecure,
		}
		cli, err = ldap.DialTLS("tcp", addr, conf)
	} else {
		cli, err = ldap.Dial("tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}

	if !enableTLS && *flagStartTLS {
		err := cli.StartTLS(&tls.Config{
			InsecureSkipVerify: *flagInsecure,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to StartTLS: %w", err)
		}
	}

	if *flagSimpleAuth {
		var pass []byte
		if *flagPromptPass {
			fmt.Printf("Enter LDAP Password: ")
			pass, err = gopass.GetPasswd()
			if err != nil {
				return nil, fmt.Errorf("getpasswd failed: %w", err)
			}
		} else {
			pass = []byte(*flagBindPass)
		}
		if err := cli.Bind(*flagBindDN, pass); err != nil {
			return nil, fmt.Errorf("bind failed: %w", err)
		}
	}

	return cli, nil
}
