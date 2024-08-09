package ldap

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"
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
		return &ProtocolError{Reason: "base response should have at least 3 values"}
	}
	code, ok := pkt.Items[0].Int()
	if !ok {
		return &ProtocolError{Reason: "invalid code in response"}
	}
	res.Code = ResultCode(code)
	res.MatchedDN, ok = pkt.Items[1].Str()
	if !ok {
		return &ProtocolError{Reason: "invalid matchedDN in response"}
	}
	res.Message, ok = pkt.Items[2].Str()
	if !ok {
		return &ProtocolError{Reason: "invalid message in response"}
	}
	return nil
}

type Server struct {
	Backend Backend
	RootDSE map[string][]string

	tlsConfig *tls.Config
	// processingTimeout is how long to allow for the execution of a request.
	processingTimeout time.Duration
	// responseTimeout is how long to allow for the response to be written to the client.
	responseTimeout time.Duration
}

type srvClient struct {
	cn         net.Conn
	wr         *bufio.Writer
	srv        *Server
	state      State
	remoteAddr net.Addr
}

func NewServer(be Backend, tlsConfig *tls.Config) (*Server, error) {
	// Copy the default RootDSE
	sf := make(map[string][]string, len(RootDSE))
	for name, vals := range RootDSE {
		sf[name] = append([]string(nil), vals...)
	}
	if tlsConfig != nil {
		sf["supportedExtension"] = append(sf["supportedExtension"], OIDStartTLS)
	}
	return &Server{
		Backend:           be,
		RootDSE:           sf,
		tlsConfig:         tlsConfig,
		processingTimeout: time.Second * 10,
		responseTimeout:   time.Second * 5,
	}, nil
}

func (srv *Server) ServeTLS(ctx context.Context, network, addr string, tlsConfig *tls.Config) error {
	if tlsConfig == nil {
		tlsConfig = srv.tlsConfig
	}
	if tlsConfig == nil {
		return errors.New("ldap: no TLS config")
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, network, addr)
	if err != nil {
		return err
	}
	return srv.serve(ctx, tls.NewListener(ln, tlsConfig))
}

func (srv *Server) Serve(ctx context.Context, network, addr string) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, network, addr)
	if err != nil {
		return err
	}
	return srv.serve(ctx, ln)
}

func (srv *Server) serve(ctx context.Context, ln net.Listener) error {
	// Close the listener when the context is canceled so Accept unblocks and
	// Serve returns.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		cn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Error("Accept failed", "err", err)
			continue
		}

		go (&srvClient{
			cn:         cn,
			wr:         bufio.NewWriter(cn),
			srv:        srv,
			remoteAddr: cn.RemoteAddr(),
		}).serve(ctx)
	}
}

func (cli *srvClient) serve(ctx context.Context) {
	// Guard against panics (e.g. malformed input) taking down the whole server.
	// Registered first so it unwinds last, after the connection has been closed.
	defer func() {
		if r := recover(); r != nil {
			slog.Error("recovered from panic serving connection", "remoteAddr", cli.remoteAddr, "panic", r)
		}
	}()

	state, err := cli.srv.Backend.Connect(cli.remoteAddr)
	if err != nil {
		if err := cli.cn.Close(); err != nil {
			slog.Error("Failed to close client connection", "remoteAddr", cli.remoteAddr, "err", err)
		}
		return
	}
	cli.state = state

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	defer func() {
		if err := cli.cn.Close(); err != nil {
			slog.Error("Failed to close client connection", "remoteAddr", cli.remoteAddr, "err", err)
		}
		if cli.state != nil {
			cli.srv.Backend.Disconnect(state)
		}
	}()

	for {
		// Timeout idle connections after 15 minutes.
		if err := cli.cn.SetReadDeadline(time.Now().Add(time.Minute * 15)); err != nil {
			slog.Error("Failed to set read deadline", "remoteAddr", cli.remoteAddr, "err", err)
		}
		pkt, _, err := ReadPacket(cli.cn)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				slog.Error("ReadPacket failed", "remoteAddr", cli.remoteAddr, "err", err)
			}
			return
		}
		if pkt.Class != ClassUniversal || pkt.Primitive || pkt.Tag != TagSequence || len(pkt.Items) < 2 {
			slog.Warn("Unknown class, primitive, tag, or too few items", "remoteAddr", cli.remoteAddr)
			return
		}

		// pkt.Format(os.Stdout)

		msgID, ok := pkt.Items[0].Int()
		if !ok {
			slog.Warn("Failed to read MessageID", "remoteAddr", cli.remoteAddr)
			return
		}

		// The optional controls element is [0] Controls following the protocolOp.
		// https://ldapwiki.com/wiki/SupportedControl
		var controlsPkt *Packet
		if len(pkt.Items) > 2 {
			if cp := pkt.Items[2]; cp.Class == ClassContext && cp.Tag == 0 && !cp.Primitive {
				controlsPkt = cp
			}
		}

		if err := cli.processRequest(ctx, msgID, pkt.Items[1], controlsPkt); err != nil {
			end := true
			if !errors.Is(err, io.EOF) {
				slog.Error("Processing of request failed", "remoteAddr", cli.remoteAddr, "err", err)
				respTag, hasResp := applicationResponseTag[pkt.Items[1].Tag]
				res := &BaseResponse{
					MessageType: respTag,
					Code:        ResultOther,
					Message:     "ERROR",
				}
				if e, ok := errors.AsType[*ProtocolError](err); ok {
					res.Code = ResultProtocolError
					res.Message = e.Reason
					end = false
				} else if e, ok := errors.AsType[*UnsupportedRequestTagError](err); ok {
					res.Code = ResultUnwillingToPerform
					res.Message = fmt.Sprintf("unsupported request tag %d", e.Tag)
					end = false
				}
				// Only send a response for operations that define one. Requests
				// such as Abandon have no response and must not be answered.
				if hasResp {
					if err := cli.cn.SetWriteDeadline(time.Now().Add(cli.srv.responseTimeout)); err != nil {
						slog.Error("Failed to set write deadline", "remoteAddr", cli.remoteAddr, "err", err)
						end = true
					} else if err := res.WritePackets(cli.wr, msgID); err != nil {
						slog.Error("Failed to write error response", "remoteAddr", cli.remoteAddr, "err", err)
						end = true
					} else if err := cli.wr.Flush(); err != nil {
						slog.Error("Failed to flush", "remoteAddr", cli.remoteAddr, "err", err)
						end = true
					} else if err := cli.cn.SetWriteDeadline(time.Time{}); err != nil {
						slog.Error("Failed to clear write deadline", "remoteAddr", cli.remoteAddr, "err", err)
						end = true
					}
				}
			}
			if end {
				return
			}
		}
	}
}

// return an error when the client connection should be closed
func (cli *srvClient) processRequest(ctx context.Context, msgID int, pkt, controlsPkt *Packet) error {
	ctx, cancel := context.WithTimeout(ctx, cli.srv.processingTimeout)
	defer cancel()

	controls, err := parseControls(controlsPkt)
	if err != nil {
		return err
	}
	// RFC 4511 4.1.11: a control marked critical that the server does not
	// recognize means the operation must not be performed; reject it with
	// unavailableCriticalExtension. Operations without a response (Unbind,
	// Abandon) cannot carry the error, so fall through and handle normally.
	if oid, ok := unsupportedCriticalControl(controls); ok {
		if respTag, hasResp := applicationResponseTag[pkt.Tag]; hasResp {
			return cli.writeResponse(msgID, &BaseResponse{
				MessageType: respTag,
				Code:        ResultUnavailableCriticalExtension,
				Message:     "unsupported critical control: " + oid,
			})
		}
	}

	// TODO: use context for deadlines and cancellations
	var res Response
	switch pkt.Tag {
	default:
		// _ = pkt.Format(os.Stdout)
		return &UnsupportedRequestTagError{Tag: pkt.Tag}
	case ApplicationUnbindRequest:
		return io.EOF
	case ApplicationBindRequest:
		// TODO: SASL
		req, err := parseBindRequest(pkt)
		if err != nil {
			return err
		}
		res, err = cli.srv.Backend.Bind(ctx, cli.state, req)
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
			res, err = cli.srv.Backend.Search(ctx, cli.state, req)
		}
		if err != nil {
			return err
		}
	case ApplicationAddRequest:
		req, err := parseAddRequest(pkt)
		if err != nil {
			return err
		}
		res, err = cli.srv.Backend.Add(ctx, cli.state, req)
		if err != nil {
			return err
		}
	case ApplicationDelRequest:
		req, err := parseDeleteRequest(pkt)
		if err != nil {
			return err
		}
		res, err = cli.srv.Backend.Delete(ctx, cli.state, req)
		if err != nil {
			return err
		}
	case ApplicationModifyRequest:
		req, err := parseModifyRequest(pkt)
		if err != nil {
			return err
		}
		res, err = cli.srv.Backend.Modify(ctx, cli.state, req)
		if err != nil {
			return err
		}
	case ApplicationModifyDNRequest:
		req, err := parseModifyDNRequest(pkt)
		if err != nil {
			return err
		}
		res, err = cli.srv.Backend.ModifyDN(ctx, cli.state, req)
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
			res, err = cli.srv.Backend.ExtendedRequest(ctx, cli.state, req)
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
			gen, err := cli.srv.Backend.PasswordModify(ctx, cli.state, r)
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
		case OIDWhoAmI:
			v, err := cli.srv.Backend.Whoami(ctx, cli.state)
			if err != nil {
				return err
			}
			res = &ExtendedResponse{
				Value: []byte(v),
			}
		}
	}
	if res == nil {
		return cli.wr.Flush()
	}
	return cli.writeResponse(msgID, res)
}

// writeResponse writes a single response message to the client under the
// configured response timeout.
func (cli *srvClient) writeResponse(msgID int, res Response) error {
	if err := cli.cn.SetWriteDeadline(time.Now().Add(cli.srv.responseTimeout)); err != nil {
		return fmt.Errorf("failed to set deadline for write: %w", err)
	}
	defer func() {
		if err := cli.cn.SetWriteDeadline(time.Time{}); err != nil {
			slog.Error("failed to clear deadline for write", "err", err)
		}
	}()
	if err := res.WritePackets(cli.wr, msgID); err != nil {
		return err
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
	// Attribute descriptions are case-insensitive, but req.Attributes holds them
	// verbatim as sent by the client. Normalize to lower case for matching.
	requested := make(map[string]bool, len(req.Attributes))
	for a := range req.Attributes {
		requested[strings.ToLower(a)] = true
	}
	for name, vals := range cli.srv.RootDSE {
		if requested["+"] || requested[strings.ToLower(name)] {
			r.Attributes[name] = make([][]byte, len(vals))
			for i, v := range vals {
				r.Attributes[name][i] = []byte(v)
			}
		}
	}
	return res, nil
}
