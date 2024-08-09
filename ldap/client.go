package ldap

// TODO: streaming search response

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
)

// ErrAlreadyTLS is returned when trying to start a TLS connection when the connection is already using TLS.
var ErrAlreadyTLS = errors.New("ldap: connection already using TLS")

// ErrConnClosed is returned for requests issued on (or in flight when) a connection that has been closed.
var ErrConnClosed = errors.New("ldap: connection closed")

func NewRequestPacket(msgID int) *Packet {
	pkt := NewPacket(ClassUniversal, false, TagSequence, nil)
	pkt.AddItem(NewPacket(ClassUniversal, true, TagInteger, msgID))
	return pkt
}

type Request interface {
	WritePackets(w io.Writer, msgID int) error
}

type packetError struct {
	msgID int
	pkt   *Packet
	err   error
}

type cliReq struct {
	i int
	r Request
}

type Client struct {
	msgID uint32
	cn    net.Conn
	wr    *bufio.Writer
	isTLS bool
	rq    chan cliReq

	// done is closed exactly once when the connection is shutting down; err
	// holds the cause and is set before done is closed, so it is safe to read
	// after observing done closed.
	closeOnce sync.Once
	done      chan struct{}
	err       error

	mu             sync.Mutex
	rmap           map[int]chan packetError
	waitNextRecvCh chan chan struct{}
	waitNextSendCh chan chan struct{}
}

// NewClient returns a new initialized client using the provided existing connection.
// The provided connection should be considered owned by the Client and not used after
// this call.
func NewClient(cn net.Conn, isTLS bool) *Client {
	c := &Client{
		cn:             cn,
		wr:             bufio.NewWriter(cn),
		msgID:          1,
		rq:             make(chan cliReq),
		done:           make(chan struct{}),
		rmap:           make(map[int]chan packetError),
		isTLS:          isTLS,
		waitNextRecvCh: make(chan chan struct{}, 1),
		waitNextSendCh: make(chan chan struct{}, 1),
	}
	c.start()
	return c
}

// Dial connects to a server that is not using TLS.
func Dial(ctx context.Context, network, address string) (*Client, error) {
	var d net.Dialer
	cn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return NewClient(cn, false), nil
}

// DialTLS connects to a server that is using TLS.
func DialTLS(ctx context.Context, network, address string, config *tls.Config) (*Client, error) {
	d := tls.Dialer{Config: config}
	cn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return NewClient(cn, true), nil
}

func (c *Client) start() {
	// Recv loop
	go func() {
		for {
			pkt, _, err := ReadPacket(c.cn)
			if err != nil {
				c.shutdown(err)
				return
			}
			if pkt.Class != ClassUniversal || pkt.Primitive || pkt.Tag != TagSequence || len(pkt.Items) < 2 {
				c.shutdown(&ProtocolError{Reason: "invalid response packet"})
				return
			}
			msgID, ok := pkt.Items[0].Int()
			if !ok {
				c.shutdown(&ProtocolError{Reason: "failed to parse msgID from response"})
				return
			}
			c.mu.Lock()
			ch := c.rmap[msgID]
			c.mu.Unlock()

			if ch == nil {
				slog.Warn("Response for unknown message ID", "msgID", msgID)
			} else {
				select {
				case ch <- packetError{msgID: msgID, pkt: pkt.Items[1]}:
				case <-c.done:
					return
				}
			}

			select {
			case ch := <-c.waitNextRecvCh:
				<-ch
			default:
			}
		}
	}()
	// Send loop
	go func() {
		for {
			var rq cliReq
			select {
			case r, ok := <-c.rq:
				if !ok {
					return
				}
				rq = r
			case <-c.done:
				return
			}
			if err := rq.r.WritePackets(c.wr, rq.i); err != nil {
				c.shutdown(err)
				return
			}
			if err := c.wr.Flush(); err != nil {
				c.shutdown(err)
				return
			}

			select {
			case ch := <-c.waitNextSendCh:
				<-ch
			default:
			}
		}
	}()
}

func (c *Client) newID() int {
	return int(atomic.AddUint32(&c.msgID, 1))
}

func (c *Client) request(ctx context.Context, req Request) (*Packet, error) {
	id := c.newID()
	ch := make(chan packetError, 1)
	// Register the response channel before the request is written so a fast
	// response can never arrive at the recv loop before the mapping exists.
	c.mu.Lock()
	c.rmap[id] = ch
	c.mu.Unlock()
	defer c.finishMessage(id)
	select {
	case c.rq <- cliReq{i: id, r: req}:
	case <-c.done:
		return nil, c.closeErr()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case r := <-ch:
		return r.pkt, r.err
	case <-c.done:
		return nil, c.closeErr()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close closes the underlying connection to the server and wakes any pending requests.
func (c *Client) Close() error {
	c.shutdown(nil)
	return c.err
}

// shutdown closes the connection exactly once, recording the cause. Pending
// requests observe the closed done channel and return c.err (or ErrConnClosed).
func (c *Client) shutdown(err error) {
	c.closeOnce.Do(func() {
		cerr := c.cn.Close()
		if err == nil {
			err = cerr
		}
		c.err = err
		close(c.done)
	})
}

func (c *Client) closeErr() error {
	if c.err != nil {
		return c.err
	}
	return ErrConnClosed
}

func (c *Client) finishMessage(msgID int) {
	c.mu.Lock()
	delete(c.rmap, msgID)
	c.mu.Unlock()
}

// StartTLS requests a TLS connection from the server. It must not be
// called concurrently with other requests.
func (c *Client) StartTLS(ctx context.Context, config *tls.Config) error {
	if c.isTLS {
		return ErrAlreadyTLS
	}
	// Tell send and recv loop to stop after the next packet
	chS := make(chan struct{})
	c.waitNextSendCh <- chS
	chR := make(chan struct{})
	c.waitNextRecvCh <- chR
	defer func() {
		select {
		case chS <- struct{}{}:
		case <-c.done:
		}
		select {
		case chR <- struct{}{}:
		case <-c.done:
		}
	}()
	pkt, err := c.request(ctx, &ExtendedRequest{
		Name: OIDStartTLS,
	})
	if err != nil {
		return err
	}
	res, err := parseExtendedResponse(pkt)
	if err != nil {
		return err
	}
	if err := res.Err(); err != nil {
		return err
	}
	tlsCn := tls.Client(c.cn, config)
	if err := tlsCn.HandshakeContext(ctx); err != nil {
		return err
	}
	c.cn = tlsCn
	c.wr.Reset(c.cn)
	return nil
}

// Bind authenticates using the provided dn and password.
func (c *Client) Bind(ctx context.Context, dn string, pass []byte) error {
	pkt, err := c.request(ctx, &BindRequest{
		DN:       dn,
		Password: pass,
	})
	if err != nil {
		return err
	}
	res, err := parseBindResponse(pkt)
	if err != nil {
		return err
	}
	return res.Err()
}

// Delete a node.
func (c *Client) Delete(ctx context.Context, dn string) error {
	pkt, err := c.request(ctx, &DeleteRequest{
		DN: dn,
	})
	if err != nil {
		return err
	}
	res, err := parseDeleteResponse(pkt)
	if err != nil {
		return err
	}
	return res.Err()
}

// Search performs a search query against the LDAP database.
func (c *Client) Search(ctx context.Context, req *SearchRequest) ([]*SearchResult, error) {
	id := c.newID()
	ch := make(chan packetError, 1)
	// Register the response channel before the request is written so a fast
	// response can never arrive at the recv loop before the mapping exists.
	c.mu.Lock()
	c.rmap[id] = ch
	c.mu.Unlock()
	defer c.finishMessage(id)
	select {
	case c.rq <- cliReq{i: id, r: req}:
	case <-c.done:
		return nil, c.closeErr()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	var results []*SearchResult
	for {
		var r packetError
		select {
		case r = <-ch:
		case <-c.done:
			return results, c.closeErr()
		case <-ctx.Done():
			return results, ctx.Err()
		}
		if r.err != nil {
			return results, r.err
		}

		switch r.pkt.Tag {
		case ApplicationSearchResultEntry:
			res, err := parseSearchResultResponse(r.pkt)
			if err != nil {
				return results, err
			}
			results = append(results, res)
		case ApplicationSearchResultReference:
			// TODO
		case ApplicationSearchResultDone:
			var res BaseResponse
			if err := parseBaseResponse(r.pkt, &res); err != nil {
				return results, err
			}
			return results, res.Err()
		default:
			return results, &ProtocolError{Reason: "unexpected tag for search response"}
		}
	}
}

// Modify operation allows a client to request that a modification
// of an entry be performed on its behalf by a server.
func (c *Client) Modify(ctx context.Context, dn string, mods []*Mod) error {
	pkt, err := c.request(ctx, &ModifyRequest{
		DN:   dn,
		Mods: mods,
	})
	if err != nil {
		return err
	}
	var res ModifyResponse
	if err := parseBaseResponse(pkt, &res.BaseResponse); err != nil {
		return err
	}
	return res.Err()
}

// WhoAmI returns the authzId for the authenticated user on the connection.
// https://tools.ietf.org/html/rfc4532
func (c *Client) WhoAmI(ctx context.Context) (string, error) {
	pkt, err := c.request(ctx, &ExtendedRequest{
		Name: OIDWhoAmI,
	})
	if err != nil {
		return "", err
	}
	res, err := parseExtendedResponse(pkt)
	if err != nil {
		return "", err
	}
	if err := res.Err(); err != nil {
		return "", err
	}
	if len(res.Value) == 0 {
		return "anonymous", nil
	}
	return string(res.Value), nil
}
