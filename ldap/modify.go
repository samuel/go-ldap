package ldap

import "io"

type ModifyRequest struct {
	DN        string
	Add       map[string][][]byte
	Delete    map[string][][]byte
	Replace   map[string][][]byte
	Increment map[string][][]byte
}

type ModifyResponse struct {
	BaseResponse
}

func parseModifyRequest(pkt *Packet) (*ModifyRequest, error) {
	if len(pkt.Items) != 2 {
		return nil, ErrProtocolError("modify request requires exactly 2 items")
	}
	dn, ok := pkt.Items[0].Str()
	if !ok {
		return nil, ErrProtocolError("invalid dn")
	}
	req := &ModifyRequest{DN: dn}
	for _, it := range pkt.Items[1].Items {
		if len(it.Items) != 2 || len(it.Items[1].Items) != 2 {
			return nil, ErrProtocolError("mod operation requires 2 items")
		}
		typ, ok := it.Items[0].Int()
		if !ok {
			return nil, ErrProtocolError("invalid mod op")
		}
		name, ok := it.Items[1].Items[0].Str()
		if !ok {
			return nil, ErrProtocolError("invalid attribute name")
		}
		values := make([][]byte, len(it.Items[1].Items[1].Items))
		for i, c := range it.Items[1].Items[1].Items {
			val, ok := c.Bytes()
			if !ok {
				return nil, ErrProtocolError("invalid attribute value")
			}
			values[i] = val
		}
		switch typ {
		case 0: // add
			if req.Add == nil {
				req.Add = make(map[string][][]byte)
			}
			req.Add[name] = append(req.Add[name], values...)
		case 1: // delete
			if req.Delete == nil {
				req.Delete = make(map[string][][]byte)
			}
			req.Delete[name] = append(req.Delete[name], values...)
		case 2: // replace
			if req.Replace == nil {
				req.Replace = make(map[string][][]byte)
			}
			req.Replace[name] = append(req.Replace[name], values...)
		case 3: // increment <http://tools.ietf.org/html/rfc4525>
			if req.Increment == nil {
				req.Increment = make(map[string][][]byte)
			}
			req.Increment[name] = append(req.Increment[name], values...)
		default:
			return nil, ErrProtocolError("unknown mod op")
		}
	}
	return req, nil
}

func (r *ModifyResponse) WritePackets(w io.Writer, msgID int) error {
	res := NewResponsePacket(msgID)
	pkt := res.AddItem(r.BaseResponse.NewPacket())
	pkt.Tag = ApplicationModifyResponse
	return res.Write(w)
}
