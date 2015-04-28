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
	msgID uint32
	cn    net.Conn
	wr    *bufio.Writer
	isTLS bool
	mu    sync.Mutex
	rq    chan cliReq
	rmap  map[int]chan packetError
}

func NewClient(cn net.Conn, isTLS bool) *Client {
	c := &Client{
		cn:    cn,
		wr:    bufio.NewWriter(cn),
		msgID: 1,
		rq:    make(chan cliReq),
		rmap:  make(map[int]chan packetError),
	}
	c.start()
	return c
}

func Dial(network, address string) (*Client, error) {
	cn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return NewClient(cn, false), nil
}

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
				e = ErrProtocolError("invalid response packet")
				break
			}
			msgID, ok := pkt.Items[0].Int()
			if !ok {
				e = ErrProtocolError("failed to parse msgID from response")
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
		}
		if e != nil {
			log.Printf(e.Error())
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

func (c *Client) Close() error {
	return c.cn.Close()
}

func (c *Client) finishMessage(msgID int) {
	c.mu.Lock()
	delete(c.rmap, msgID)
	c.mu.Unlock()
}

// func (c *Client) StartTLS(config *tls.Config) error {
// 	if c.isTLS {
// 		return ErrAlreadyTLS
// 	}
// 	// TODO
// 	return errors.New("ldap: StartTLS not yet supported")
// }

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
			return results, ErrProtocolError("unexpected tag for search response")
		}
	}
}

// func (c *Client) Unbind() error {
// 	// TODO
// 	return c.Close()
// }
