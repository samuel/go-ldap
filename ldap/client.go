package ldap

// TODO: streaming search response

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
)

// ErrAlreadyTLS is returned when trying to start a TLS connection when the connection is already using TLS
var ErrAlreadyTLS = errors.New("ldap: connection already using TLS")

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
	c chan packetError
}

type Client struct {
	msgID          uint32
	cn             net.Conn
	wr             *bufio.Writer
	isTLS          bool
	mu             sync.Mutex
	rq             chan cliReq
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
		rmap:           make(map[int]chan packetError),
		isTLS:          isTLS,
		waitNextRecvCh: make(chan chan struct{}, 1),
		waitNextSendCh: make(chan chan struct{}, 1),
	}
	c.start()
	return c
}

// Dial connects to a server that is not using TLS.
func Dial(network, address string) (*Client, error) {
	cn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return NewClient(cn, false), nil
}

// DialTLS connects to a server that is using TLS.
func DialTLS(network, address string, config *tls.Config) (*Client, error) {
	cn, err := tls.Dial(network, address, config)
	if err != nil {
		return nil, err
	}
	return NewClient(cn, true), nil
}

func (c *Client) start() {
	// Recv loop
	go func() {
		defer func() {
			c.cn.Close()
		}()
		var e error
		for {
			pkt, _, err := ReadPacket(c.cn)
			if err != nil {
				e = err
				break
			}
			if pkt.Class != ClassUniversal || pkt.Primitive || pkt.Tag != TagSequence || len(pkt.Items) < 2 {
				e = ProtocolError("invalid response packet")
				break
			}
			msgID, ok := pkt.Items[0].Int()
			if !ok {
				e = ProtocolError("failed to parse msgID from response")
				break
			}
			c.mu.Lock()
			ch := c.rmap[msgID]
			c.mu.Unlock()

			if ch == nil {
				log.Printf("Response for unknown message ID %d", msgID)
			} else {
				ch <- packetError{msgID: msgID, pkt: pkt.Items[1]}
			}

			select {
			case ch := <-c.waitNextRecvCh:
				<-ch
			default:
			}
		}
		if e != nil {
			log.Printf("ldap: error on receive: %s", e)
		}
	}()
	// Send loop
	go func() {
		defer func() {
			c.cn.Close()
		}()
		for {
			rq, ok := <-c.rq
			if !ok {
				break
			}
			if err := rq.r.WritePackets(c.wr, rq.i); err != nil {
				rq.c <- packetError{err: err}
				break
			}
			if err := c.wr.Flush(); err != nil {
				rq.c <- packetError{err: err}
				break
			}

			c.mu.Lock()
			c.rmap[rq.i] = rq.c
			c.mu.Unlock()

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

func (c *Client) request(req Request) (*Packet, error) {
	id := c.newID()
	ch := make(chan packetError, 1)
	c.rq <- cliReq{
		i: id,
		r: req,
		c: ch,
	}
	r := <-ch
	c.finishMessage(id)
	return r.pkt, r.err
}

// Close closes the underlying connection to the server
func (c *Client) Close() error {
	return c.cn.Close()
}

func (c *Client) finishMessage(msgID int) {
	c.mu.Lock()
	delete(c.rmap, msgID)
	c.mu.Unlock()
}

// StartTLS requests a TLS connection from the server. It must not be
// called concurrently with other requests.
func (c *Client) StartTLS(config *tls.Config) error {
	if c.isTLS {
		return ErrAlreadyTLS
	}
	// Tell send and recv loop to stop after the next packet
	chS := make(chan struct{})
	c.waitNextSendCh <- chS
	chR := make(chan struct{})
	c.waitNextRecvCh <- chR
	defer func() {
		chS <- struct{}{}
		chR <- struct{}{}
	}()
	pkt, err := c.request(&ExtendedRequest{
		Name: OIDStartTLS,
	})
	if err != nil {
		return err
	}
	res, err := parseExtendedResponse(pkt)
	if err != nil {
		return err
	}
	if err := res.BaseResponse.Err(); err != nil {
		return err
	}
	tlsCn := tls.Client(c.cn, config)
	if err := tlsCn.Handshake(); err != nil {
		return err
	}
	c.cn = tlsCn
	c.wr.Reset(c.cn)
	return nil
}

// Bind authenticates using the provided dn and password.
func (c *Client) Bind(dn string, pass []byte) error {
	pkt, err := c.request(&BindRequest{
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
	return res.BaseResponse.Err()
}

// Delete a node
func (c *Client) Delete(dn string) error {
	pkt, err := c.request(&DeleteRequest{
		DN: dn,
	})
	if err != nil {
		return err
	}
	res, err := parseDeleteResponse(pkt)
	if err != nil {
		return err
	}
	return res.BaseResponse.Err()
}

// Search performs a search query against the LDAP database.
func (c *Client) Search(req *SearchRequest) ([]*SearchResult, error) {
	id := c.newID()
	ch := make(chan packetError, 1)
	c.rq <- cliReq{
		i: id,
		r: req,
		c: ch,
	}
	defer c.finishMessage(id)

	var results []*SearchResult
	for {
		r := <-ch
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
			return results, ProtocolError("unexpected tag for search response")
		}
	}
}

// Modify operation allows a client to request that a modification
// of an entry be performed on its behalf by a server.
func (c *Client) Modify(dn string, mods []*Mod) error {
	pkt, err := c.request(&ModifyRequest{
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
	return res.BaseResponse.Err()
}

// WhoAmI returns the authzId for the authenticated user on the connection.
// https://tools.ietf.org/html/rfc4532
func (c *Client) WhoAmI() (string, error) {
	pkt, err := c.request(&ExtendedRequest{
		Name: OIDWhoAmI,
	})
	if err != nil {
		return "", err
	}
	res, err := parseExtendedResponse(pkt)
	if err != nil {
		return "", err
	}
	if err := res.BaseResponse.Err(); err != nil {
		return "", err
	}
	if len(res.Value) == 0 {
		return "anonymous", nil
	}
	return string(res.Value), nil
}
