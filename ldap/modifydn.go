package ldap

import "io"

type ModifyDNRequest struct {
	DN           string
	NewRDN       string
	DeleteOldRDN bool
	NewSuperior  string
}

type ModifyDNResponse struct {
	BaseResponse
}

func parseModifyDNRequest(pkt *Packet) (*ModifyDNRequest, error) {
	if len(pkt.Items) < 3 || len(pkt.Items) > 4 {
		return nil, ProtocolError("wrong number of items")
	}
	var ok bool
	req := &ModifyDNRequest{}
	req.DN, ok = pkt.Items[0].Str()
	if !ok {
		return nil, ProtocolError("invalid dn")
	}
	req.NewRDN, ok = pkt.Items[1].Str()
	if !ok {
		return nil, ProtocolError("invalid newrdn")
	}
	req.DeleteOldRDN, ok = pkt.Items[2].Bool()
	if !ok {
		return nil, ProtocolError("invalid deleteoldrdn")
	}
	if len(pkt.Items) == 4 {
		req.NewSuperior, ok = pkt.Items[3].Str()
		if !ok {
			return nil, ProtocolError("invalid newSuperior")
		}
	}
	return req, nil
}

func (r *ModifyDNResponse) WritePackets(w io.Writer, msgID int) error {
	res := NewResponsePacket(msgID)
	pkt := res.AddItem(r.BaseResponse.NewPacket())
	pkt.Tag = ApplicationModifyDNResponse
	return res.Write(w)
}
