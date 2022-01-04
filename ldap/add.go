package ldap

import "io"

type AddRequest struct {
	DN         string
	Attributes map[string][][]byte
}

type AddResponse struct {
	BaseResponse
}

func parseAddRequest(pkt *Packet) (*AddRequest, error) {
	if len(pkt.Items) != 2 {
		return nil, ProtocolError("add request requires 2 items")
	}
	var ok bool
	req := &AddRequest{}
	req.DN, ok = pkt.Items[0].Str()
	if !ok {
		return nil, ProtocolError("invalid dn")
	}
	req.Attributes = make(map[string][][]byte)
	for _, at := range pkt.Items[1].Items {
		if len(at.Items) != 2 {
			return nil, ProtocolError("invalid attribute")
		}
		attrName, ok := at.Items[0].Str()
		if !ok {
			return nil, ProtocolError("invalid attribute")
		}
		var vals [][]byte
		for _, v := range at.Items[1].Items {
			vb, ok := v.Bytes()
			if !ok {
				return nil, ProtocolError("invalid attribute value")
			}
			vals = append(vals, vb)
		}
		req.Attributes[attrName] = vals
	}
	return req, nil
}

func (r *AddResponse) WritePackets(w io.Writer, msgID int) error {
	res := NewResponsePacket(msgID)
	pkt := res.AddItem(r.BaseResponse.NewPacket())
	pkt.Tag = ApplicationAddResponse
	return res.Write(w)
}
