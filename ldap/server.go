package ldap

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

func NewResponsePacket(msgID int) *Packet {
	pkt := NewPacket(ClassUniversal, false, TagSequence, nil)
	pkt.AddItem(NewPacket(ClassUniversal, true, TagInteger, msgID))
	return pkt
}

type Response interface {
	WritePackets(w io.Writer, msgID int) error
}

type BaseResponse struct {
	MessageType int
	Code        ResultCode
	MatchedDN   string
	Message     string
	// TODO Referral
}

func (r *BaseResponse) Error() string {
	return fmt.Sprintf("ldap: %s: %s", r.Code.String(), r.Message)
}

func (r *BaseResponse) Err() error {
	if r.Code == 0 {
		return nil
	}
	return r
}

func (r *BaseResponse) WritePackets(w io.Writer, msgID int) error {
	pkt := NewResponsePacket(msgID)
	pkt.AddItem(r.NewPacket())
	return pkt.Write(w)
}

func (r *BaseResponse) NewPacket() *Packet {
	pkt := NewPacket(ClassApplication, false, r.MessageType, nil)
	pkt.AddItem(NewPacket(ClassUniversal, true, TagEnumerated, int(r.Code)))
	pkt.AddItem(NewPacket(ClassUniversal, true, TagOctetString, r.MatchedDN))
	pkt.AddItem(NewPacket(ClassUniversal, true, TagOctetString, r.Message))
	return pkt
}

func parseBaseResponse(pkt *Packet, res *BaseResponse) error {
	if len(pkt.Items) < 3 {
		return ErrProtocolError("base response should have at least 3 values")
	}
	code, ok := pkt.Items[0].Int()
	if !ok {
		return ErrProtocolError("invalid code in response")
	}
	res.Code = ResultCode(code)
	res.MatchedDN, ok = pkt.Items[1].Str()
	if !ok {
		return ErrProtocolError("invalid matchedDN in response")
	}
	res.Message, ok = pkt.Items[2].Str()
	if !ok {
		return ErrProtocolError("invalid message in response")
	}
	return nil
}

type Server struct {
	Backend Backend
	RootDSE map[string][]string

	tlsConfig *tls.Config
}

type srvClient struct {
	cn  net.Conn
	wr  *bufio.Writer
	srv *Server
	ctx Context
}

func NewServer(be Backend, tlsConfig *tls.Config) (*Server, error) {
	// Copy the default RootDSE
	sf := make(map[string][]string, len(RootDSE))
	for name, vals := range RootDSE {
		v := make([]string, len(vals))
		for i, x := range vals {
			v[i] = x
		}
		sf[name] = v
	}
	if tlsConfig != nil {
		sf["supportedExtension"] = append(sf["supportedExtension"], OIDStartTLS)
	}
	return &Server{
		Backend:   be,
		RootDSE:   sf,
		tlsConfig: tlsConfig,
	}, nil
}

func (srv *Server) ServeTLS(network, addr string, tlsConfig *tls.Config) error {
	if tlsConfig == nil {
		tlsConfig = srv.tlsConfig
	}
	if tlsConfig == nil {
		return errors.New("ldap: no TLS config")
	}
	ln, err := tls.Listen(network, addr, tlsConfig)
	if err != nil {
		return err
	}
	return srv.serve(ln)
}

func (srv *Server) Serve(network, addr string) error {
	ln, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return srv.serve(ln)
}

func (srv *Server) serve(ln net.Listener) error {
	for {
		cn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept failed: %+v", err)
			continue
		}

		go (&srvClient{
			cn:  cn,
			wr:  bufio.NewWriter(cn),
			srv: srv,
		}).serve()
	}
}

func (cli *srvClient) serve() {
	ctx, err := cli.srv.Backend.Connect(cli.cn.RemoteAddr())
	if err != nil {
		cli.cn.Close()
		return
	}
	cli.ctx = ctx

	defer func() {
		cli.cn.Close()
		if cli.ctx != nil {
			cli.srv.Backend.Disconnect(ctx)
		}
	}()

	for {
		pkt, _, err := ReadPacket(cli.cn)
		if err != nil {
			if err != io.EOF {
				log.Printf("ReadPacket failed: %s", err.Error())
			}
			return
		}
		if pkt.Class != ClassUniversal || pkt.Primitive || pkt.Tag != TagSequence || len(pkt.Items) < 2 {
			log.Print("Unknown classtype, tagtype, tag, or too few items")
			return
		}

		// pkt.Format(os.Stdout)

		msgID, ok := pkt.Items[0].Int()
		if !ok {
			log.Printf("Failed to read MessageID")
			return
		}

		if err := cli.processRequest(msgID, pkt.Items[1]); err != nil {
			end := true
			if err != io.EOF {
				log.Printf("Processing of request failed: %s", err.Error())
				res := &BaseResponse{
					MessageType: pkt.Items[1].Tag + 1,
					Code:        ResultOther,
					Message:     "ERROR",
				}
				switch e := err.(type) {
				case ErrProtocolError:
					res.Code = ResultProtocolError
					res.Message = string(e)
					end = false
				case ErrUnsupportedRequestTag:
					res.Code = ResultUnwillingToPerform
					res.Message = fmt.Sprintf("unsupported request tag %d", int(e))
					end = false
				}
				if err := res.WritePackets(cli.wr, msgID); err != nil {
					log.Printf("Failed to write error response: %s", err)
				}
				if err := cli.wr.Flush(); err != nil {
					log.Printf("Failed to flush: %s", err)
				}
			}
			if end {
				return
			}
		}
	}
}

// return an error when the client connection should be closed
func (cli *srvClient) processRequest(msgID int, pkt *Packet) error {
	var res Response
	switch pkt.Tag {
	default:
		pkt.Format(os.Stdout)
		return ErrUnsupportedRequestTag(pkt.Tag)
	case ApplicationUnbindRequest:
		return io.EOF
	case ApplicationBindRequest:
		// TODO: SASL
		req, err := parseBindRequest(pkt)
		if err != nil {
			return err
		}
		res, err = cli.srv.Backend.Bind(cli.ctx, req)
		if err != nil {
			return err
		}
	case ApplicationSearchRequest:
		req, err := parseSearchRequest(pkt)
		if err != nil {
			return err
		}
		if req.BaseDN == "" && req.Scope == ScopeBaseObject { // TODO check filter
			res, err = cli.rootDSE(req)
		} else {
			res, err = cli.srv.Backend.Search(cli.ctx, req)
		}
		if err != nil {
			return err
		}
	case ApplicationAddRequest:
		req, err := parseAddRequest(pkt)
		if err != nil {
			return err
		}
		res, err = cli.srv.Backend.Add(cli.ctx, req)
		if err != nil {
			return err
		}
	case ApplicationDelRequest:
		req, err := parseDeleteRequest(pkt)
		if err != nil {
			return err
		}
		res, err = cli.srv.Backend.Delete(cli.ctx, req)
		if err != nil {
			return err
		}
	case ApplicationModifyRequest:
		req, err := parseModifyRequest(pkt)
		if err != nil {
			return err
		}
		res, err = cli.srv.Backend.Modify(cli.ctx, req)
		if err != nil {
			return err
		}
	case ApplicationModifyDNRequest:
		req, err := parseModifyDNRequest(pkt)
		if err != nil {
			return err
		}
		res, err = cli.srv.Backend.ModifyDN(cli.ctx, req)
		if err != nil {
			return err
		}
	case ApplicationExtendedRequest:
		req, err := parseExtendedRequest(pkt)
		if err != nil {
			return err
		}

		switch req.Name {
		default:
			res, err = cli.srv.Backend.ExtendedRequest(cli.ctx, req)
			if err != nil {
				return err
			}
		case OIDStartTLS:
			if cli.srv.tlsConfig == nil {
				res = &ExtendedResponse{
					BaseResponse: BaseResponse{
						Code:    ResultUnavailable,
						Message: "TLS not configured",
					},
					Name: OIDStartTLS,
				}
			} else {
				res = &ExtendedResponse{
					Name: OIDStartTLS,
				}
				if err := res.WritePackets(cli.wr, msgID); err != nil {
					return err
				}
				if err := cli.wr.Flush(); err != nil {
					return err
				}
				cli.cn = tls.Server(cli.cn, cli.srv.tlsConfig)
				cli.wr.Reset(cli.cn)
				return nil
			}
		case OIDPasswordModify:
			var r *PasswordModifyRequest
			if len(req.Value) != 0 {
				p, _, err := ParsePacket(req.Value)
				if err != nil {
					return err
				}
				r, err = parsePasswordModifyRequest(p)
				if err != nil {
					return err
				}
			} else {
				r = &PasswordModifyRequest{}
			}
			gen, err := cli.srv.Backend.PasswordModify(cli.ctx, r)
			if err != nil {
				return err
			}
			p := NewPacket(ClassUniversal, false, TagSequence, nil)
			if gen != nil {
				p.AddItem(NewPacket(ClassContext, true, 0, gen))
			}
			b, err := p.Encode()
			if err != nil {
				return err
			}
			res = &ExtendedResponse{
				Value: b,
			}
		case OIDWhoami:
			v, err := cli.srv.Backend.Whoami(cli.ctx)
			if err != nil {
				return err
			}
			res = &ExtendedResponse{
				Value: []byte(v),
			}
		}
	}
	if res != nil {
		if err := res.WritePackets(cli.wr, msgID); err != nil {
			return err
		}
	}
	return cli.wr.Flush()
}

func (cli *srvClient) rootDSE(req *SearchRequest) (*SearchResponse, error) {
	r := &SearchResult{DN: "", Attributes: make(map[string][][]byte)}
	res := &SearchResponse{Results: []*SearchResult{r}}
	if len(req.Attributes) == 0 {
		r.Attributes["objectClass"] = [][]byte{[]byte("top")}
		return res, nil
	}
	for name, vals := range cli.srv.RootDSE {
		if req.Attributes["+"] || req.Attributes[strings.ToLower(name)] {
			r.Attributes[name] = make([][]byte, len(vals))
			for i, v := range vals {
				r.Attributes[name][i] = []byte(v)
			}
		}
	}
	return res, nil
}
