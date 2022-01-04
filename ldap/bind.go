package ldap

import "io"

type BindRequest struct {
	DN       string
	Password []byte
	// TODO: SASL
}

type BindResponse struct {
	BaseResponse
}

func parseBindRequest(pkt *Packet) (*BindRequest, error) {
	if len(pkt.Items) != 3 {
		return nil, ProtocolError("bind request should have 3 values")
	}
	ver, ok := pkt.Items[0].Int()
	if !ok || ver != protocolVersion {
		return nil, ProtocolError("unsupported or invalid version")
	}
	req := &BindRequest{}
	if req.DN, ok = pkt.Items[1].Str(); !ok {
		return nil, ProtocolError("can't parse dn for bind request")
	}
	if req.Password, ok = pkt.Items[2].Bytes(); !ok {
		return nil, ProtocolError("can't parse simple password for bind request")
	}
	// TODO: SASL
	return req, nil
}

func parseBindResponse(pkt *Packet) (*BindResponse, error) {
	res := &BindResponse{}
	if err := parseBaseResponse(pkt, &res.BaseResponse); err != nil {
		return nil, err
	}
	return res, nil
}

func (r *BindResponse) WritePackets(w io.Writer, msgID int) error {
	res := NewResponsePacket(msgID)
	pkt := res.AddItem(r.BaseResponse.NewPacket())
	pkt.Tag = ApplicationBindResponse
	return res.Write(w)
}

func (r *BindRequest) WritePackets(w io.Writer, msgID int) error {
	pkt := NewPacket(ClassApplication, false, ApplicationBindRequest, nil)
	pkt.AddItem(NewPacket(ClassUniversal, true, TagInteger, protocolVersion))
	pkt.AddItem(NewPacket(ClassUniversal, true, TagOctetString, r.DN))
	pkt.AddItem(NewPacket(ClassContext, true, 0, r.Password))

	req := NewRequestPacket(msgID)
	req.AddItem(pkt)
	return req.Write(w)
}
